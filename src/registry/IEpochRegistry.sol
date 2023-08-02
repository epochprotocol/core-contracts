// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../helpers/UserOperationHelper.sol";
import "./IConditionChecker.sol";

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
