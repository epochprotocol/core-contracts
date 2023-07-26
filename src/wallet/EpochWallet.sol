// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "openzeppelin/utils/cryptography/ECDSA.sol";
import "openzeppelin/proxy/utils/Initializable.sol";
import "openzeppelin/proxy/utils/UUPSUpgradeable.sol";
import "account-abstraction/core/BaseAccount.sol";
import {CustomUserOperationLib} from "../helpers/UserOperationHelper.sol";
import "../callback/TokenCallbackHandler.sol";

import "../registry/IEpochRegistry.sol";

/**
 * minimal account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 *  has a single signer that can send requests through the entryPoint.
 */
contract EpochWallet is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;
    using CustomUserOperationLib for UserOperation;

    address public owner;
    bytes4 private constant _EXECUTE_EPOCH_SELECTOR = bytes4(uint32(0x2cd28dcb));
    bytes4 private constant _EXECUTE_EPOCH_BATCH_SELECTOR = bytes4(uint32(0x3dcdb59d));
    IEntryPoint private immutable _entryPoint;
    IEpochRegistry private _epochRegistry;

    event EpochWalletInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    function epochRegistry() public view virtual returns (IEpochRegistry) {
        return _epochRegistry;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a transaction from epoch protocol
     */
    function executeEpoch(uint256 taskId, address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();

        (bool _send, address _dest, uint256 _value, bytes memory _func) =
            _epochRegistry.processTransaction(taskId, dest, value, func);
        _requireEpochVerification(_send);
        _call(_dest, _value, _func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, uint256[] calldata values, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();

        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
        }
    }

    /**
     * execute a sequence of transactions from epoch protocol
     */
    function executeBatchEpoch(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        (bool _send, address[] memory _dest, uint256[] memory _values, bytes[] memory _func) =
            _epochRegistry.processBatchTransaction(taskId, dest, values, func);
        _requireEpochVerification(_send);

        for (uint256 i = 0; i < _dest.length; i++) {
            _call(_dest[i], _values[i], _func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of EpochWallet must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner, IEpochRegistry anEpochRegistry) public virtual initializer {
        _initialize(anOwner, anEpochRegistry);
    }

    function _initialize(address anOwner, IEpochRegistry anEpochRegistry) internal virtual {
        owner = anOwner;
        _epochRegistry = anEpochRegistry;
        emit EpochWalletInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    // Require the function call went through EntryPoint or owner
    function _requireEpochVerification(bool _send) internal pure {
        require(_send, "account: Condition Failed");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes4 selector = bytes4(userOp.callData[4:]);
        if (selector == _EXECUTE_EPOCH_SELECTOR || selector == _EXECUTE_EPOCH_BATCH_SELECTOR) {
            bytes32 userOpHashWithoutNonce = userOp.hashWithoutNonce();
            bytes32 hash = userOpHashWithoutNonce.toEthSignedMessageHash();
            address signer = hash.recover(userOp.signature);
            if (owner != signer) return SIG_VALIDATION_FAILED;
            uint256 taskId;
            if (selector == _EXECUTE_EPOCH_SELECTOR) {
                (taskId,,,) = abi.decode(userOp.callData[4:], (uint256, address, uint256, bytes));
            } else {
                (taskId,,,) = abi.decode(userOp.callData[4:], (uint256, address[], uint256[], bytes[]));
            }
            bool _send = _epochRegistry.verifyTransaction(taskId, userOp);
            if (_send) return 0;
            return 1;
        } else {
            bytes32 hash = userOpHash.toEthSignedMessageHash();
            address signer = hash.recover(userOp.signature);
            if (owner != signer) return SIG_VALIDATION_FAILED;
            return 0;
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }

    function updateRegistry(IEpochRegistry _registry) external {
        _requireFromEntryPointOrOwner();
        require(address(_registry) != address(0), "Factory: Address must be valid");
        _epochRegistry = _registry;
    }
}
