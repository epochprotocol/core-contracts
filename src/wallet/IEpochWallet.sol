// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */
import "account-abstraction/interfaces/IAccount.sol";

import "account-abstraction/interfaces/IEntryPoint.sol";

import "../registry/IEpochRegistry.sol";

/**
 * minimal account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 *  has a single signer that can send requests through the entryPoint.
 */
interface IEpochWallet is IAccount {
    function owner() external returns (address);

    event EpochWalletInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner
    );

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
    function executeEpoch(
        uint256 taskId,
        address dest,
        uint256 value,
        bytes calldata func
    ) external;

    /**
     * execute a sequence of transactions
     */
    function executeBatch(
        address[] calldata dest,
        bytes[] calldata func
    ) external;

    /**
     * execute a sequence of transactions from epoch protocol
     */
    function executeBatchEpoch(
        uint256 taskId,
        address[] calldata dest,
        bytes[] calldata func
    ) external;

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
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) external;
}
