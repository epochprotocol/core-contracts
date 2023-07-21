// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;
import "./IEpochRegistry.sol";

contract EpochRegistry is IEpochRegistry {
    mapping(uint256 => bool) public taskStatus;

    function verifyTransaction(
        uint256 taskId,
        address dest,
        uint256 value,
        bytes calldata func
    ) external returns (bool _send) {
        _send = true;

        //updated taskID here
    }

    function processTransaction(
        uint256 taskId,
        address dest,
        uint256 value,
        bytes calldata func
    )
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

    function verifyBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external returns (bool _send) {
        //updated taskID here
        _send = true;
    }

    function processBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    )
        external
        returns (
            bool _send,
            address[] memory _dest,
            uint256[] memory _values,
            bytes[] memory _func
        )
    {
        //updated taskID here
        _send = true;
        _dest = dest;
        _func = func;
        _values = values;

        //updated taskID here

        taskStatus[taskId] = true;
    }
}
