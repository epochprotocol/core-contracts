// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

interface IEpochRegistry {
    function taskStatus(uint256) external returns (bool);

    function verifyTransaction(
        uint256 taskId,
        address dest,
        uint256 value,
        bytes calldata func
    ) external returns (bool _send);

    function verifyBatchTransaction(
        uint256 taskId,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata func
    ) external returns (bool _send);

    function processTransaction(
        uint256 taskId,
        address dest,
        uint256 value,
        bytes calldata func
    )
        external
        returns (bool _send, address _dest, uint256 _value, bytes memory _func);

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
        );
}
