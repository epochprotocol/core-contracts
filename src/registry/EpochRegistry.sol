// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./IEpochRegistry.sol";
import "../helpers/UserOperationHelper.sol";
import "../wallet/IEpochWallet.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";

contract EpochRegistry is IEpochRegistry {
    using ECDSA for bytes32;
    using CustomUserOperationLib for UserOperation;

    bytes4 private constant _EXECUTE_EPOCH_SELECTOR = bytes4(uint32(0x2cd28dcb));
    bytes4 private constant _EXECUTE_EPOCH_BATCH_SELECTOR = bytes4(uint32(0x3dcdb59d));

    uint256 taskIdCounter = 1;
    uint256 executionWindowCounter = 1;
    uint256 onChainConditionCounter = 1;
    uint256 dataSourceCounter = 1;
    mapping(uint256 => bool) public taskStatus;
    mapping(uint256 => Task) public taskMapping;
    mapping(uint256 => ExecutionWindow) public executionWindowMapping;
    mapping(uint256 => OnChainCondition) public onChainConditionMapping;
    mapping(uint256 => DataSource) public dataSourceMapping;

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
            executionWindowCounter++;
        } else if (onChainCondition.useOnChainCondition) {
            onChainConditionMapping[onChainConditionCounter] = onChainCondition;
            task.onChainConditionId = onChainConditionCounter;
            onChainConditionCounter++;
        }
        if (dataSource.useDataSource) {
            dataSourceMapping[dataSourceCounter] = dataSource;
            task.dataSourceId = dataSourceCounter;
            dataSourceCounter++;
        }
        taskMapping[task.taskId] = task;
        return task.taskId;
    }

    function verifyTransaction(uint256 taskId, UserOperation calldata userOperation) external returns (bool _send) {
        bytes32 hash = userOperation.hashWithoutNonce();
        Task memory task = taskMapping[taskId];
        IEpochWallet wallet = IEpochWallet(payable(msg.sender));
        address owner = wallet.owner();
        require(owner == hash.recover(userOperation.signature), "Registry: Invalid Signature");
        bytes4 selector = bytes4(userOperation.callData[4:]);
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

        _send = true;
    }

    function processTransaction(uint256 taskId, address dest, uint256 value, bytes calldata func)
        external
        returns (bool _send, address _dest, uint256 _value, bytes memory _func)
    {
        _send = true;
        _dest = dest;
        _value = value;
        _func = func;
        //updated taskID here

        taskStatus[taskId] = true;
    }

    function processBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external returns (bool _send, address[] memory _dest, uint256[] memory _values, bytes[] memory _func) {
        //updated taskID here
        _send = true;
        _dest = dest;
        _func = func;
        _values = values;

        //updated taskID here

        taskStatus[taskId] = true;
    }
}
