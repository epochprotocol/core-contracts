// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable no-inline-assembly */

/* solhint-disable no-inline-assembly */

/**
 * returned data from validateUserOp.
 * validateUserOp returns a uint256, with is created by `_packedValidationData` and parsed by `_parseValidationData`
 * @param aggregator - address(0) - the account validated the signature by itself.
 *              address(1) - the account failed to validate the signature.
 *              otherwise - this is an address of a signature aggregator that must be used to validate the signature.
 * @param validAfter - this UserOp is valid only after this timestamp.
 * @param validaUntil - this UserOp is valid only up to this timestamp.
 */
struct ValidationData {
    address aggregator;
    uint48 validAfter;
    uint48 validUntil;
}

//extract sigFailed, validAfter, validUntil.
// also convert zero validUntil to type(uint48).max
function _parseValidationData(uint256 validationData) pure returns (ValidationData memory data) {
    address aggregator = address(uint160(validationData));
    uint48 validUntil = uint48(validationData >> 160);
    if (validUntil == 0) {
        validUntil = type(uint48).max;
    }
    uint48 validAfter = uint48(validationData >> (48 + 160));
    return ValidationData(aggregator, validAfter, validUntil);
}

// intersect account and paymaster ranges.
function _intersectTimeRange(uint256 validationData, uint256 paymasterValidationData)
    pure
    returns (ValidationData memory)
{
    ValidationData memory accountValidationData = _parseValidationData(validationData);
    ValidationData memory pmValidationData = _parseValidationData(paymasterValidationData);
    address aggregator = accountValidationData.aggregator;
    if (aggregator == address(0)) {
        aggregator = pmValidationData.aggregator;
    }
    uint48 validAfter = accountValidationData.validAfter;
    uint48 validUntil = accountValidationData.validUntil;
    uint48 pmValidAfter = pmValidationData.validAfter;
    uint48 pmValidUntil = pmValidationData.validUntil;

    if (validAfter < pmValidAfter) validAfter = pmValidAfter;
    if (validUntil > pmValidUntil) validUntil = pmValidUntil;
    return ValidationData(aggregator, validAfter, validUntil);
}

/**
 * helper to pack the return value for validateUserOp
 * @param data - the ValidationData to pack
 */
function _packValidationData(ValidationData memory data) pure returns (uint256) {
    return uint160(data.aggregator) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
}

/**
 * helper to pack the return value for validateUserOp, when not using an aggregator
 * @param sigFailed - true for signature failure, false for success
 * @param validUntil last timestamp this UserOperation is valid (or zero for infinite)
 * @param validAfter first timestamp this UserOperation is valid
 */
function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) pure returns (uint256) {
    return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
}

/**
 * keccak function over calldata.
 * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
 */
function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

/* solhint-disable no-inline-assembly */

/**
 * User Operation struct
 * @param sender the sender account of this request.
 * @param nonce unique value the sender uses to verify it is not a replay.
 * @param initCode if set, the account contract will be created by this constructor/
 * @param callData the method call to execute on this account.
 * @param callGasLimit the gas limit passed to the callData method call.
 * @param verificationGasLimit gas used for validateUserOp and validatePaymasterUserOp.
 * @param preVerificationGas gas not calculated by the handleOps method, but added to the gas paid. Covers batch overhead.
 * @param maxFeePerGas same as EIP-1559 gas parameter.
 * @param maxPriorityFeePerGas same as EIP-1559 gas parameter.
 * @param paymasterAndData if set, this field holds the paymaster address and paymaster-specific data. the paymaster will pay for the transaction instead of the sender.
 * @param signature sender-verified signature over the entire request, the EntryPoint address and the chain ID.
 */
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library UserOperationLib {
    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    //relayer/block builder might submit the TX with higher priorityFee, but the user should not
    // pay above what he signed for.
    function gasPrice(UserOperation calldata userOp) internal view returns (uint256) {
        unchecked {
            uint256 maxFeePerGas = userOp.maxFeePerGas;
            uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function hash(UserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library CustomUserOperationLib {
    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    //relayer/block builder might submit the TX with higher priorityFee, but the user should not
    // pay above what he signed for.
    function gasPrice(UserOperation calldata userOp) internal view returns (uint256) {
        unchecked {
            uint256 maxFeePerGas = userOp.maxFeePerGas;
            uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function packWithoutNonce(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            hashInitCode,
            hashCallData,
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function hash(UserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }

    function hashWithoutNonce(UserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(packWithoutNonce(userOp));
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

interface IConditionChecker {
    function checkCondition(bytes memory userInput, bytes memory onChainCondition) external returns (bool);
}

interface IEpochRegistry {
    enum DataType {
        STRING,
        STRING_STATIC_ARRAY,
        STRING_DYNAMIC_ARRAY,
        ADDRESS,
        ADDRESS_STATIC_ARRAY,
        ADDRESS_DYNAMIC_ARRAY,
        UINT,
        UINT_STATIC_ARRAY,
        UINT_DYNAMIC_ARRAY,
        BYTES,
        BYTES_STATIC_ARRAY,
        BYTES_DYNAMIC_ARRAY,
        BOOL,
        BOOL_STATIC_ARRAY,
        BOOL_DYNAMIC_ARRAY
    }

    struct Task {
        uint256 taskId;
        bool isBatchTransaction;
        address taskOwner;
        address destination;
        uint256 timeConditionId;
        uint256 onChainConditionId;
        uint256 dataSourceId;
        address[] destinations;
    }

    struct ExecutionWindow {
        bool useExecutionWindow;
        bool recurring;
        uint64 recurrenceGap;
        uint64 executionWindowStart;
        uint64 executionWindowEnd;
    }

    struct OnChainCondition {
        bool useOnChainCondition;
        uint32 dataPosition;
        address dataSource;
        IConditionChecker conditionChecker;
        DataType dataType;
        bytes encodedQuery;
        bytes encodedCondition;
    }

    struct DataSource {
        bool useDataSource;
        uint32 dataPosition;
        uint32 positionInCallData;
        address dataSource;
        bytes encodedQuery;
    }

    function taskStatus(uint256) external returns (bool);

    function verifyTransaction(uint256 taskId, UserOperation calldata userOperation) external returns (bool _send);

    function processTransaction(uint256 taskId, address dest, uint256 value, bytes calldata func)
        external
        returns (bool _send, address _dest, uint256 _value, bytes memory _func);
    function addTask(
        address destination,
        bool isBatchTransaction,
        ExecutionWindow memory executionWindowCondition,
        OnChainCondition memory onChainCondition,
        DataSource memory dataSource,
        address[] memory destinations
    ) external returns (uint256);

    function processBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external returns (bool _send, address[] memory _dest, uint256[] memory _values, bytes[] memory _func);
}

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

interface IAccount {
    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
     * @param userOp the operation that is about to be executed.
     * @param userOpHash hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds missing funds on the account's deposit in the entrypoint.
     *      This is the minimum amount to transfer to the sender(entryPoint) to be able to make the call.
     *      The excess is left as a deposit in the entrypoint, for future calls.
     *      can be withdrawn anytime using "entryPoint.withdrawTo()"
     *      In case there is a paymaster in the request (or the current deposit is high enough), this value will be zero.
     * @return validationData packaged ValidationData structure. use `_packValidationData` and `_unpackValidationData` to encode and decode
     *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *         otherwise, an address of an "authorizer" contract.
     *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *      <6-byte> validAfter - first timestamp this operation is valid
     *      If an account doesn't use time-range, it is enough to return SIG_VALIDATION_FAILED value (1) for signature failure.
     *      Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData);
}

/**
 * Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 * Only one instance required on each chain.
 *
 */
// SPDX-License-Identifier: GPL-3.0

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

/**
 * manage deposits and stakes.
 * deposit is just a balance used to pay for UserOperations (either by a paymaster or an account)
 * stake is value locked for at least "unstakeDelay" by the staked entity.
 */
interface IStakeManager {
    event Deposited(address indexed account, uint256 totalDeposit);

    event Withdrawn(address indexed account, address withdrawAddress, uint256 amount);

    /// Emitted when stake or unstake delay are modified
    event StakeLocked(address indexed account, uint256 totalStaked, uint256 unstakeDelaySec);

    /// Emitted once a stake is scheduled for withdrawal
    event StakeUnlocked(address indexed account, uint256 withdrawTime);

    event StakeWithdrawn(address indexed account, address withdrawAddress, uint256 amount);

    /**
     * @param deposit the entity's deposit
     * @param staked true if this entity is staked.
     * @param stake actual amount of ether staked for this entity.
     * @param unstakeDelaySec minimum delay to withdraw the stake.
     * @param withdrawTime - first block timestamp where 'withdrawStake' will be callable, or zero if already locked
     * @dev sizes were chosen so that (deposit,staked, stake) fit into one cell (used during handleOps)
     *    and the rest fit into a 2nd cell.
     *    112 bit allows for 10^15 eth
     *    48 bit for full timestamp
     *    32 bit allows 150 years for unstake delay
     */
    struct DepositInfo {
        uint112 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    //API struct used by getStakeInfo and simulateValidation
    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelaySec;
    }

    /// @return info - full deposit information of given account
    function getDepositInfo(address account) external view returns (DepositInfo memory info);

    /// @return the deposit (for gas payment) of the account
    function balanceOf(address account) external view returns (uint256);

    /**
     * add to the deposit of the given account
     */
    function depositTo(address account) external payable;

    /**
     * add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param _unstakeDelaySec the new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 _unstakeDelaySec) external payable;

    /**
     * attempt to unlock the stake.
     * the value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external;

    /**
     * withdraw from the (unlocked) stake.
     * must first call unlockStake and wait for the unstakeDelay to pass
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external;

    /**
     * withdraw from the deposit.
     * @param withdrawAddress the address to send withdrawn value.
     * @param withdrawAmount the amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
}

/**
 * Aggregated Signatures validator.
 */
interface IAggregator {
    /**
     * validate aggregated signature.
     * revert if the aggregated signature does not match the given list of operations.
     */
    function validateSignatures(UserOperation[] calldata userOps, bytes calldata signature) external view;

    /**
     * validate signature of a single userOp
     * This method is should be called by bundler after EntryPoint.simulateValidation() returns (reverts) with ValidationResultWithAggregation
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp the userOperation received from the user.
     * @return sigForUserOp the value to put into the signature field of the userOp when calling handleOps.
     *    (usually empty, unless account and aggregator support some kind of "multisig"
     */
    function validateUserOpSignature(UserOperation calldata userOp) external view returns (bytes memory sigForUserOp);

    /**
     * aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code perform this aggregation
     * @param userOps array of UserOperations to collect the signatures from.
     * @return aggregatedSignature the aggregated signature
     */
    function aggregateSignatures(UserOperation[] calldata userOps)
        external
        view
        returns (bytes memory aggregatedSignature);
}

interface INonceManager {
    /**
     * Return the next nonce for this sender.
     * Within a given key, the nonce values are sequenced (starting with zero, and incremented by one on each userop)
     * But UserOp with different keys can come with arbitrary order.
     *
     * @param sender the account address
     * @param key the high 192 bit of the nonce
     * @return nonce a full nonce to pass for next UserOp with this sender.
     */
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    /**
     * Manually increment the nonce of the sender.
     * This method is exposed just for completeness..
     * Account does NOT need to call it, neither during validation, nor elsewhere,
     * as the EntryPoint will update the nonce regardless.
     * Possible use-case is call it with various keys to "initialize" their nonces to one, so that future
     * UserOperations will not pay extra for the first transaction with a given key.
     */
    function incrementNonce(uint192 key) external;
}

interface IEntryPoint is IStakeManager, INonceManager {
    /**
     *
     * An event emitted after each successful request
     * @param userOpHash - unique identifier for the request (hash its entire content, except signature).
     * @param sender - the account that generates this request.
     * @param paymaster - if non-null, the paymaster that pays for this request.
     * @param nonce - the nonce value from the request.
     * @param success - true if the sender transaction succeeded, false if reverted.
     * @param actualGasCost - actual amount paid (by account or paymaster) for this UserOperation.
     * @param actualGasUsed - total gas used by this UserOperation (including preVerification, creation, validation and execution).
     */
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    /**
     * account "sender" was deployed.
     * @param userOpHash the userOp that deployed this account. UserOperationEvent will follow.
     * @param sender the account that is deployed
     * @param factory the factory used to deploy this account (in the initCode)
     * @param paymaster the paymaster used by this UserOp
     */
    event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster);

    /**
     * An event emitted if the UserOperation "callData" reverted with non-zero length
     * @param userOpHash the request unique identifier.
     * @param sender the sender of this request
     * @param nonce the nonce used in the request
     * @param revertReason - the return bytes from the (reverted) call to "callData".
     */
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    /**
     * an event emitted by handleOps(), before starting the execution loop.
     * any event emitted before this event, is part of the validation.
     */
    event BeforeExecution();

    /**
     * signature aggregator used by the following UserOperationEvents within this bundle.
     */
    event SignatureAggregatorChanged(address indexed aggregator);

    /**
     * a custom revert error of handleOps, to identify the offending op.
     *  NOTE: if simulateValidation passes successfully, there should be no reason for handleOps to fail on it.
     *  @param opIndex - index into the array of ops to the failed one (in simulateValidation, this is always zero)
     *  @param reason - revert reason
     *      The string starts with a unique code "AAmn", where "m" is "1" for factory, "2" for account and "3" for paymaster issues,
     *      so a failure can be attributed to the correct entity.
     *   Should be caught in off-chain handleOps simulation and not happen on-chain.
     *   Useful for mitigating DoS attempts against batchers or for troubleshooting of factory/account/paymaster reverts.
     */
    error FailedOp(uint256 opIndex, string reason);

    /**
     * error case when a signature aggregator fails to verify the aggregated signature it had created.
     */
    error SignatureValidationFailed(address aggregator);

    /**
     * Successful result from simulateValidation.
     * @param returnInfo gas and time-range returned values
     * @param senderInfo stake information about the sender
     * @param factoryInfo stake information about the factory (if any)
     * @param paymasterInfo stake information about the paymaster (if any)
     */
    error ValidationResult(ReturnInfo returnInfo, StakeInfo senderInfo, StakeInfo factoryInfo, StakeInfo paymasterInfo);

    /**
     * Successful result from simulateValidation, if the account returns a signature aggregator
     * @param returnInfo gas and time-range returned values
     * @param senderInfo stake information about the sender
     * @param factoryInfo stake information about the factory (if any)
     * @param paymasterInfo stake information about the paymaster (if any)
     * @param aggregatorInfo signature aggregation info (if the account requires signature aggregator)
     *      bundler MUST use it to verify the signature, or reject the UserOperation
     */
    error ValidationResultWithAggregation(
        ReturnInfo returnInfo,
        StakeInfo senderInfo,
        StakeInfo factoryInfo,
        StakeInfo paymasterInfo,
        AggregatorStakeInfo aggregatorInfo
    );

    /**
     * return value of getSenderAddress
     */
    error SenderAddressResult(address sender);

    /**
     * return value of simulateHandleOp
     */
    error ExecutionResult(
        uint256 preOpGas, uint256 paid, uint48 validAfter, uint48 validUntil, bool targetSuccess, bytes targetResult
    );

    //UserOps handled, per aggregator
    struct UserOpsPerAggregator {
        UserOperation[] userOps;
        // aggregator address
        IAggregator aggregator;
        // aggregated signature
        bytes signature;
    }

    /**
     * Execute a batch of UserOperation.
     * no signature aggregator is used.
     * if any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops the operations to execute
     * @param beneficiary the address to receive the fees
     */
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator the operations to execute, grouped by aggregator (or address(0) for no-aggregator accounts)
     * @param beneficiary the address to receive the fees
     */
    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary)
        external;

    /**
     * generate a request Id - unique identifier for this request.
     * the request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     */
    function getUserOpHash(UserOperation calldata userOp) external view returns (bytes32);

    /**
     * Simulate a call to account.validateUserOp and paymaster.validatePaymasterUserOp.
     * @dev this method always revert. Successful result is ValidationResult error. other errors are failures.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage outside the account's data.
     * @param userOp the user operation to validate.
     */
    function simulateValidation(UserOperation calldata userOp) external;

    /**
     * gas and return values during simulation
     * @param preOpGas the gas used for validation (including preValidationGas)
     * @param prefund the required prefund for this operation
     * @param sigFailed validateUserOp's (or paymaster's) signature check failed
     * @param validAfter - first timestamp this UserOp is valid (merging account and paymaster time-range)
     * @param validUntil - last timestamp this UserOp is valid (merging account and paymaster time-range)
     * @param paymasterContext returned by validatePaymasterUserOp (to be passed into postOp)
     */
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        bool sigFailed;
        uint48 validAfter;
        uint48 validUntil;
        bytes paymasterContext;
    }

    /**
     * returned aggregated signature info.
     * the aggregator returned by the account, and its current stake.
     */
    struct AggregatorStakeInfo {
        address aggregator;
        StakeInfo stakeInfo;
    }

    /**
     * Get counterfactual sender address.
     *  Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * this method always revert, and returns the address in SenderAddressResult error
     * @param initCode the constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes memory initCode) external;

    /**
     * simulate full execution of a UserOperation (including both validation and target execution)
     * this method will always revert with "ExecutionResult".
     * it performs full validation of the UserOperation, but ignores signature error.
     * an optional target address is called after the userop succeeds, and its value is returned
     * (before the entire call is reverted)
     * Note that in order to collect the the success/failure of the target call, it must be executed
     * with trace enabled to track the emitted events.
     * @param op the UserOperation to simulate
     * @param target if nonzero, a target address to call after userop simulation. If called, the targetSuccess and targetResult
     *        are set to the return from that call.
     * @param targetCallData callData to pass to target address
     */
    function simulateHandleOp(UserOperation calldata op, address target, bytes calldata targetCallData) external;
}

/**
 * minimal account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 *  has a single signer that can send requests through the entryPoint.
 */
interface IEpochWallet is IAccount {
    function owner() external returns (address);

    event EpochWalletInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    function entryPoint() external view returns (IEntryPoint);

    function epochRegistry() external view returns (IEpochRegistry);

    // solhint-disable-next-line no-empty-blocks
    receive() external payable;

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external;

    /**
     * execute a transaction from epoch protocol
     */
    function executeEpoch(uint256 taskId, address dest, uint256 value, bytes calldata func) external;

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external;

    /**
     * execute a sequence of transactions from epoch protocol
     */
    function executeBatchEpoch(uint256 taskId, address[] calldata dest, bytes[] calldata func) external;

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of EpochWallet must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) external;

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() external view returns (uint256);

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() external payable;

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) external;

    function updateRegistry(IEpochRegistry _registry) external;
}

// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)

// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Down, // Toward negative infinity
        Up, // Toward infinity
        Zero // Toward zero
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds up instead
     * of rounding down.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)
     * with further edits by Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            require(denominator > prod1, "Math: mulDiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.
            // See https://cs.stackexchange.com/q/138556/92363.

            // Does not overflow because the denominator cannot be zero at this stage in the function.
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works
            // in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256, rounded down, of a positive value.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);
        }
    }
}

// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toString(int256 value) internal pure returns (string memory) {
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV // Deprecated in v4.8
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            data := keccak256(ptr, 0x42)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Data with intended validator, created from a
     * `validator` and `data` according to the version 0 of EIP-191.
     *
     * See {recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x00", validator, data));
    }
}

library ByteManipulationLibrary {
    uint8 constant byteLength = 32;

    //position starts from zero
    /**
     * @notice extract static length data like uint256, address
     * @param data abi encoded bytes calldata
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function getFixedData(bytes calldata data, uint256 position) external pure returns (bytes32) {
        uint256 initialPosition = position * byteLength;
        uint256 endingPosition = initialPosition + byteLength;
        return bytes32(data[initialPosition:endingPosition]);
    }

    /**
     * @notice extract dynamic length data like string and bytes
     * @param data abi encoded bytes calldata
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function getDynamicData(bytes calldata data, uint256 position) external pure returns (bytes memory) {
        uint256 initialPosition = (position * byteLength);
        uint256 endingPosition = initialPosition + byteLength;
        uint256 dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));

        uint256 dataStart = dataPosition;

        uint256 dataLengthEndPosition = dataStart + byteLength;

        uint256 length = uint256(bytes32(data[dataStart:dataLengthEndPosition]));
        bytes memory extractedData = new bytes(length);
        uint256 _start = dataLengthEndPosition;
        uint256 _end = _start + length;
        extractedData = data[_start:_end];
        return extractedData;
    }

    /**
     * @notice extract a dynamic length array of static sized data like uint256, address etc.
     * @param data abi encoded bytes calldata
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function getFixedSizeDynamicArrayData(bytes calldata data, uint256 position)
        external
        pure
        returns (bytes[] memory)
    {
        uint256 _start;
        uint256 _end;
        uint256 offset;
        uint256 dataPosition;
        uint256 dataPositionEnd;
        uint256 anchor;

        {
            uint256 initialPosition = (position * byteLength);
            uint256 endingPosition = initialPosition + byteLength;
            dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));
            anchor = dataPosition;
            dataPositionEnd = dataPosition + byteLength;
            offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
            _start = anchor + offset;
            _end = _start + byteLength;
        }
        uint256 arrayElements = uint256(offset / byteLength);
        bytes[] memory extractedData = new bytes[](arrayElements);
        {
            for (uint256 i = 0; i < arrayElements; i++) {
                uint256 elementLength = uint256(bytes32(data[_start:_end]));
                bytes memory element = bytes(data[_end:_end + elementLength]);
                extractedData[i] = bytes(element);
                dataPosition = dataPositionEnd;
                dataPositionEnd = dataPosition + byteLength;
                offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
                _start = anchor + offset;
                _end = _start + byteLength;
            }
        }
        return extractedData;
    }

    /**
     * @notice extract a static sized array of static sized data like uint256, address.
     * @param data abi encoded bytes calldata
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function getStaticArrayData(bytes calldata data, uint256 position) external pure returns (bytes[] memory) {
        uint256 initialPosition = (position * byteLength);
        uint256 endingPosition = initialPosition + byteLength;
        uint256 dataPosition = uint256(bytes32(data[initialPosition:endingPosition]));

        uint256 dataStart = dataPosition;

        uint256 dataLengthEndPosition = dataStart + byteLength;

        uint256 length = uint256(bytes32(data[dataStart:dataLengthEndPosition]));
        bytes[] memory extractedData = new bytes[](length);
        uint256 _start = dataLengthEndPosition;
        uint256 _end = _start + byteLength;
        for (uint256 i = 0; i < length; i++) {
            extractedData[i] = data[_start:_end];
            _start = _end;
            _end = _start + byteLength;
        }
        return extractedData;
    }

    /**
     * @notice extract a dynamic sized array of dynamic sized data.
     * @param data abi encoded bytes calldata
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function getDynamicSizeDynamicArrayData(bytes calldata data, uint256 position)
        external
        pure
        returns (bytes[] memory)
    {
        uint256 _start;
        uint256 _end;
        uint256 offset;
        uint256 dataPosition;
        uint256 dataPositionEnd;
        uint256 anchor;
        uint256 arrayElements;

        {
            uint256 initialPosition = (position * byteLength);
            uint256 endingPosition = initialPosition + byteLength;

            uint256 lengthValueStart = uint256(bytes32(data[initialPosition:endingPosition]));
            uint256 lengthValueEnd = lengthValueStart + byteLength;
            arrayElements = uint256(bytes32(data[lengthValueStart:lengthValueEnd]));
            dataPosition = lengthValueEnd;
            dataPositionEnd = dataPosition + byteLength;
            anchor = lengthValueEnd;
            offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
            _start = anchor + offset;
            _end = _start + byteLength;
        }
        bytes[] memory extractedData = new bytes[](arrayElements);
        {
            for (uint256 i = 0; i < arrayElements; i++) {
                uint256 elementLength = uint256(bytes32(data[_start:_end]));
                bytes memory element = bytes(data[_end:_end + elementLength]);
                extractedData[i] = bytes(element);
                dataPosition = dataPositionEnd;
                dataPositionEnd = dataPosition + byteLength;
                offset = uint256(bytes32(data[dataPosition:dataPositionEnd]));
                _start = anchor + offset;
                _end = _start + byteLength;
            }
        }
        return extractedData;
    }

    /**
     * @notice overwrite static data over a specific position in bytes encoded data with signature
     * @param data abi encoded bytes calldata
     * @param dataToOverwrite data to place at a given position
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function overwriteStaticDataWithSignature(bytes calldata data, bytes32 dataToOverwrite, uint32 position)
        external
        pure
        returns (bytes memory)
    {
        uint32 positionStart = 4 + (position * byteLength);
        uint32 positionEnd = positionStart + byteLength;
        bytes calldata firstSplit = data[0:positionStart];
        bytes calldata secondSplit = data[positionEnd:data.length];
        bytes memory firstConcat = bytes.concat(firstSplit, dataToOverwrite);
        return bytes.concat(firstConcat, secondSplit);
    }

    /**
     * @notice overwrite static data over a specific position in bytes encoded data without signature
     * @param data abi encoded bytes calldata
     * @param dataToOverwrite data to place at a given position
     * @param position position of the data to be extracted
     * @return returns bytes of extracted data.
     *
     */
    function overwriteStaticDataWithoutSignature(bytes calldata data, bytes32 dataToOverwrite, uint32 position)
        external
        pure
        returns (bytes memory)
    {
        uint32 positionStart = (position * byteLength);
        uint32 positionEnd = positionStart + byteLength;
        bytes calldata firstSplit = data[0:positionStart];
        bytes calldata secondSplit = data[positionEnd:data.length];
        bytes memory firstConcat = bytes.concat(firstSplit, dataToOverwrite);
        return bytes.concat(firstConcat, secondSplit);
    }
}

contract EpochRegistry is IEpochRegistry {
    using ECDSA for bytes32;
    using CustomUserOperationLib for UserOperation;
    using ByteManipulationLibrary for bytes;

    bytes4 private constant _EXECUTE_EPOCH_SELECTOR = bytes4(uint32(0x0b1aee18));
    bytes4 private constant _EXECUTE_EPOCH_BATCH_SELECTOR = bytes4(uint32(0xa42d15f4));

    uint256 taskIdCounter = 1;
    uint256 executionWindowCounter = 1;
    uint256 onChainConditionCounter = 1;
    uint256 dataSourceCounter = 1;
    mapping(uint256 => bool) public taskStatus;
    mapping(uint256 => bool) public taskDeleted;

    mapping(uint256 => Task) public taskMapping;
    mapping(uint256 => ExecutionWindow) public executionWindowMapping;
    mapping(uint256 => OnChainCondition) public onChainConditionMapping;
    mapping(uint256 => DataSource) public dataSourceMapping;

    event NewTask(Task task);
    event TaskDeleted(Task task);

    event NewExecutionWindow(uint256 indexed id, ExecutionWindow window);
    event NewOnChainCondition(uint256 indexed id, OnChainCondition condition);
    event NewDataSource(uint256 indexed id, DataSource dataSource);

    event TaskProcessed(uint256 indexed id);

    //dont send data source for batched transactions
    //op hash without nonce
    function addTask(
        address destination,
        bool isBatchTransaction,
        ExecutionWindow memory executionWindowCondition,
        OnChainCondition memory onChainCondition,
        DataSource memory dataSource,
        address[] memory destinations
    ) public returns (uint256) {
        require(
            executionWindowCondition.useExecutionWindow || onChainCondition.useOnChainCondition,
            "Registry: no condition provided"
        );
        if (isBatchTransaction) {
            require(destinations.length > 0, "Registry: Batch Transactions need destinations");
            require(dataSource.useDataSource == false, "Registry: batch transactions can not use external data source");
        } else {
            require(destination != address(0), "Registry: Invalid destination");
        }
        Task memory task = Task({
            taskId: taskIdCounter,
            isBatchTransaction: isBatchTransaction,
            destination: destination,
            taskOwner: msg.sender,
            timeConditionId: 0,
            onChainConditionId: 0,
            dataSourceId: 0,
            destinations: destinations
        });
        taskIdCounter++;
        if (executionWindowCondition.useExecutionWindow) {
            executionWindowMapping[executionWindowCounter] = executionWindowCondition;
            task.timeConditionId = executionWindowCounter;
            emit NewExecutionWindow(executionWindowCounter, executionWindowCondition);
            executionWindowCounter++;
        } else if (onChainCondition.useOnChainCondition) {
            onChainConditionMapping[onChainConditionCounter] = onChainCondition;
            task.onChainConditionId = onChainConditionCounter;
            emit NewOnChainCondition(onChainConditionCounter, onChainCondition);
            onChainConditionCounter++;
        }
        if (dataSource.useDataSource) {
            dataSourceMapping[dataSourceCounter] = dataSource;
            task.dataSourceId = dataSourceCounter;
            emit NewDataSource(dataSourceCounter, dataSource);

            dataSourceCounter++;
        }
        taskMapping[task.taskId] = task;
        taskStatus[task.taskId] = false;
        emit NewTask(task);
        return task.taskId;
    }

    function verifyTransaction(uint256 taskId, UserOperation calldata userOperation) external returns (bool _send) {
        require(taskStatus[taskId] == false, "Registry: task already executed");
        bytes32 hash = userOperation.hashWithoutNonce().toEthSignedMessageHash();
        Task memory task = taskMapping[taskId];
        IEpochWallet wallet = IEpochWallet(payable(msg.sender));
        address owner = wallet.owner();
        require(task.taskOwner == msg.sender, "Registry: No the task owner");
        require(owner == hash.recover(userOperation.signature), "Registry: Invalid Signature");
        bytes4 selector = bytes4(userOperation.callData[:4]);
        if (task.isBatchTransaction) {
            require(selector == _EXECUTE_EPOCH_BATCH_SELECTOR, "Registry: Transaction not batch transaction");
            (, address[] memory dest,,) =
                abi.decode(userOperation.callData[4:], (uint256, address[], uint256[], bytes[]));
            require(
                keccak256(abi.encode(task.destinations)) == keccak256(abi.encode(dest)),
                "Registry: Invalid Destiantion Array"
            );
        } else {
            require(selector == _EXECUTE_EPOCH_SELECTOR, "Registry: Invalid Function Call");
            (, address dest,,) = abi.decode(userOperation.callData[4:], (uint256, address, uint256, bytes));

            require(task.destination == dest, "Registry: Invalid Destination");
        }
        //check condition
        if (task.timeConditionId != 0) {
            ExecutionWindow memory timeCondition = executionWindowMapping[task.timeConditionId];
            require(timeCondition.executionWindowStart < block.timestamp, "Registry: Time start Condition Failiure");
            require(timeCondition.executionWindowEnd > block.timestamp, "Registry: Time end Condition Failiure");
        } else if (task.onChainConditionId != 0) {
            OnChainCondition memory onChainCondition = onChainConditionMapping[task.onChainConditionId];
            bool _onChainConditionStatus = _checkOnChainCondition(onChainCondition);
            require(_onChainConditionStatus, "Registry: On-chain Condition Failed");
        }

        _send = true;
    }

    function _checkOnChainCondition(OnChainCondition memory onChainCondition) internal returns (bool) {
        (bool success, bytes memory response) = onChainCondition.dataSource.call(onChainCondition.encodedQuery);
        require(success, "Registry: Invalid OnChainCondition");
        return onChainCondition.conditionChecker.checkCondition(onChainCondition.encodedCondition, response);
    }

    function processTransaction(uint256 taskId, address dest, uint256 value, bytes calldata func)
        external
        returns (bool _send, address _dest, uint256 _value, bytes memory _func)
    {
        require(taskStatus[taskId] == false, "Registry: Task already executed");
        require(taskMapping[taskId].taskId == taskId, "Registry: Task does not exist");

        Task memory task = taskMapping[taskId];
        _func = func;

        if (task.dataSourceId != 0) {
            DataSource memory dataSource = dataSourceMapping[task.dataSourceId];
            _func = _fetchData(dataSource, _func);
        }
        _send = true;
        _dest = dest;
        _value = value;
        //updated taskID here
        ExecutionWindow memory executionWindow = executionWindowMapping[task.timeConditionId];
        if (executionWindow.recurring) {
            executionWindow.executionWindowStart += executionWindow.recurrenceGap;
            executionWindow.executionWindowEnd += executionWindow.recurrenceGap;
            executionWindowMapping[task.timeConditionId] = executionWindow;
        } else {
            taskStatus[taskId] = true;
        }
        emit TaskProcessed(taskId);
    }

    function _fetchData(DataSource memory dataSource, bytes memory _func) internal returns (bytes memory) {
        (bool status, bytes memory response) = dataSource.dataSource.call(dataSource.encodedQuery);
        require(status, "Registry: data fetch failed");
        bytes32 dataToOverwrite = response.getFixedData(dataSource.dataPosition);
        bytes memory overwrittenData =
            _func.overwriteStaticDataWithSignature(dataToOverwrite, dataSource.positionInCallData);
        return overwrittenData;
    }

    function processBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external returns (bool _send, address[] memory _dest, uint256[] memory _values, bytes[] memory _func) {
        require(taskStatus[taskId] == false, "Registry: Task already executed");
        Task memory task = taskMapping[taskId];
        require(task.taskId == taskId, "Registry: Task does not exist");
        //updated taskID here
        _send = true;
        _dest = dest;
        _func = func;
        _values = values;

        //updated taskID here

        ExecutionWindow memory executionWindow = executionWindowMapping[task.timeConditionId];
        if (executionWindow.recurring) {
            executionWindow.executionWindowStart += executionWindow.recurrenceGap;
            executionWindow.executionWindowEnd += executionWindow.recurrenceGap;
            executionWindowMapping[task.timeConditionId] = executionWindow;
        } else {
            taskStatus[taskId] = true;
        }
        emit TaskProcessed(taskId);
    }

    function deleteTask(uint256 taskId) external {
        Task memory task = taskMapping[taskId];
        require(task.taskOwner == msg.sender, "Registry: not the task owner");
        require(task.taskId == taskId, "Registry: task does not exist");
        taskStatus[taskId] = true;
        taskDeleted[taskId] = true;
        delete taskMapping[taskId];
        emit TaskDeleted(task);
    }
}
