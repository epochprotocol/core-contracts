// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./IEpochRegistry.sol";
import "../helpers/UserOperationHelper.sol";
import "../wallet/IEpochWallet.sol";
import "./IConditionChecker.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import "encoded-data-manipulation-lib/ByteManipulationLibrary.sol";

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
    mapping(uint256 => Task) public taskMapping;
    mapping(uint256 => ExecutionWindow) public executionWindowMapping;
    mapping(uint256 => OnChainCondition) public onChainConditionMapping;
    mapping(uint256 => DataSource) public dataSourceMapping;

    event NewTask(Task task);
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

        taskStatus[taskId] = true;
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
        require(taskMapping[taskId].taskId == taskId, "Registry: Task does not exist");
        //updated taskID here
        _send = true;
        _dest = dest;
        _func = func;
        _values = values;

        //updated taskID here

        taskStatus[taskId] = true;
        emit TaskProcessed(taskId);
    }
}
