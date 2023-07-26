// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../src/registry/EpochRegistry.sol";
import "../src/wallet/EpochWallet.sol";
import "../src/wallet/EpochWalletFactory.sol";
import "account-abstraction/interfaces/UserOperation.sol";
import "account-abstraction/test/TestUtil.sol";

contract EpochRegistryTest is Test {
    using UserOperationLib for UserOperation;
    using ECDSA for bytes32;

    EpochWallet public wallet;
    EpochWalletFactory public factory;
    EpochRegistry public registry;

    uint256 public mainnetFork;
    address public immutable adEntrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public immutable salt = 123456;

    address private immutable deployer = 0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84;
    string mnemonic;
    uint256 privateKey;

    constructor() {
        string memory mainnetUrl = vm.envString("MAINNET_RPC_URL");
        mainnetFork = vm.createFork(mainnetUrl);
        registry = new EpochRegistry();
        IEntryPoint ept = IEntryPoint(adEntrypoint);
        EpochWallet walletImpl = new EpochWallet(ept);
        factory = new EpochWalletFactory(walletImpl, registry);
        wallet = factory.createAccount(address(this), salt);
        hoax(address(wallet), 100 ether);
        mnemonic = vm.envString("TEST_MNEMONIC");
        privateKey = vm.deriveKey(mnemonic, 0);
    }

    function testAddTimeBasedTask() external {
        // initializing task
        address destination = deployer;
        bool isBatchTransaction = false;

        IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
            useExecutionWindow: true,
            recurring: true,
            recurrenceGap: 10000,
            executionWindowStart: 10000,
            executionWindowEnd: 100000000
        });
        IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
            useOnChainCondition: false,
            dataPosition: 0,
            dataSource: address(0),
            dataType: IEpochRegistry.DataType.STRING,
            encodedCallData: new bytes(0),
            encodedQuery: new bytes(0)
        });
        IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
            useDataSource: false,
            dataPosition: 0,
            positionInCallData: 0,
            dataSource: address(0),
            dataType: IEpochRegistry.StaticDataType.UINT,
            encodedQuery: new bytes(0)
        });
        address[] memory destinations = new address[](0);

        vm.prank(address(wallet));
        uint256 taskId = registry.addTask(
            destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
        );
        (
            uint256 _taskId,
            bool _isBatchTransaction,
            address _taskOwner,
            address _destination,
            uint256 _timeConditionId,
            uint256 _onChainConditionId,
            uint256 _dataSourceId
        ) = registry.taskMapping(taskId);
        {
            assertEq(taskId, _taskId);
            assertEq(isBatchTransaction, _isBatchTransaction);
            assertEq(address(wallet), _taskOwner);
            assertEq(destination, _destination);
            {
                (
                    bool useExecutionWindow,
                    bool recurring,
                    uint64 recurrenceGap,
                    uint64 executionWindowStart,
                    uint64 executionWindowEnd
                ) = registry.executionWindowMapping(_timeConditionId);
                assertEq(useExecutionWindow, true);
                assertEq(recurring, true);
                assertEq(recurrenceGap, 10000);
                assertEq(executionWindowStart, 10000);
                assertEq(executionWindowEnd, 100000000);
            }
        }
        {
            (
                bool _useOnChainCondition,
                uint32 _dataPosition,
                address _dataSource,
                IEpochRegistry.DataType _dataType,
                bytes memory _encodedCallData,
                bytes memory _encodedQuery
            ) = registry.onChainConditionMapping(_onChainConditionId);
            assertEq(_useOnChainCondition, false);
            assertEq(_dataPosition, 0);
            assertEq(_dataSource, address(0));
            assertEq(uint256(_dataType), uint256(IEpochRegistry.DataType.STRING));
            assertEq(_encodedCallData, new bytes(0));
            assertEq(_encodedQuery, new bytes(0));
        }
        {
            (
                bool _useDataSource,
                uint32 __dataPosition,
                uint32 _positionInCallData,
                address __dataSource,
                IEpochRegistry.StaticDataType __dataType,
                bytes memory __encodedQuery
            ) = registry.dataSourceMapping(_dataSourceId);
            assertEq(_useDataSource, false);
            assertEq(__dataPosition, 0);
            assertEq(_positionInCallData, 0);
            assertEq(__dataSource, address(0));
            assertEq(uint256(__dataType), uint256(IEpochRegistry.DataType.STRING));
            assertEq(__encodedQuery, new bytes(0));
        }
    }
}
