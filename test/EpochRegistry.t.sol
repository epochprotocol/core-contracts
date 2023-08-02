// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../src/registry/EpochRegistry.sol";
import "../src/wallet/EpochWallet.sol";
import "../src/wallet/EpochWalletFactory.sol";
import {CustomUserOperationLib, UserOperation} from "../src/helpers/UserOperationHelper.sol";
import "account-abstraction/test/TestUtil.sol";
import "../src/registry/IConditionChecker.sol";
import "../src/registry/conditions/EqualityChecker.sol";
import "./DummyData.sol";

contract EpochRegistryTest is Test {
    using CustomUserOperationLib for UserOperation;
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
    address customAddress;
    mapping(uint256 => bool) gotFallback;
    mapping(uint256 => uint256) gotTestCall;

    address[] destinations;
    uint256[] values;
    bytes[] datas;

    receive() external payable {}

    fallback() external payable {
        uint256 data = abi.decode(msg.data, (uint256));
        gotFallback[data] = true;
    }

    constructor() {
        string memory mainnetUrl = vm.envString("MAINNET_RPC_URL");
        mainnetFork = vm.createFork(mainnetUrl);
        registry = new EpochRegistry();
        IEntryPoint ept = IEntryPoint(adEntrypoint);
        EpochWallet walletImpl = new EpochWallet(ept);
        factory = new EpochWalletFactory(walletImpl, registry);
        mnemonic = vm.envString("TEST_MNEMONIC");
        privateKey = vm.deriveKey(mnemonic, 0);
        customAddress = vm.addr(privateKey);
        wallet = factory.createAccount(customAddress, salt);
        hoax(address(wallet), 100 ether);
        // vm.prank(customAddress);
    }

    function dummyCall(uint256 taskId, uint256 testNumber) external {
        gotTestCall[taskId] = testNumber;
    }

    function testAddTask() external {
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
            conditionChecker: IConditionChecker(address(0)),
            dataPosition: 0,
            dataSource: address(0),
            dataType: IEpochRegistry.DataType.STRING,
            encodedQuery: new bytes(0),
            encodedCondition: new bytes(0)
        });
        IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
            useDataSource: false,
            dataPosition: 0,
            positionInCallData: 0,
            dataSource: address(0),
            encodedQuery: new bytes(0)
        });

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
                IConditionChecker _conditionChecker,
                IEpochRegistry.DataType _dataType,
                bytes memory _encodedQuery,
                bytes memory _encodedCondition
            ) = registry.onChainConditionMapping(_onChainConditionId);
            assertEq(_useOnChainCondition, false);
            assertEq(_dataPosition, 0);
            assertEq(_dataSource, address(0));
            assertEq(uint256(_dataType), uint256(IEpochRegistry.DataType.STRING));
            assertEq(_encodedQuery, new bytes(0));
            assertEq(_encodedCondition, new bytes(0));
            assertEq(address(_conditionChecker), address(0));
        }
        {
            (
                bool _useDataSource,
                uint32 __dataPosition,
                uint32 _positionInCallData,
                address __dataSource,
                bytes memory __encodedQuery
            ) = registry.dataSourceMapping(_dataSourceId);
            assertEq(_useDataSource, false);
            assertEq(__dataPosition, 0);
            assertEq(_positionInCallData, 0);
            assertEq(__dataSource, address(0));
            assertEq(__encodedQuery, new bytes(0));
        }
    }

    function testValidateBatchTransaction() external {
        // initializing task
        address destination = address(this);
        bool isBatchTransaction = true;

        IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
            useExecutionWindow: true,
            recurring: true,
            recurrenceGap: 10000,
            executionWindowStart: 0,
            executionWindowEnd: 100000000
        });
        IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
            useOnChainCondition: false,
            conditionChecker: IConditionChecker(address(0)),
            dataPosition: 0,
            dataSource: address(0),
            dataType: IEpochRegistry.DataType.STRING,
            encodedQuery: new bytes(0),
            encodedCondition: new bytes(0)
        });
        IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
            useDataSource: false,
            dataPosition: 0,
            positionInCallData: 0,
            dataSource: address(0),
            encodedQuery: new bytes(0)
        });

        vm.prank(address(wallet));
        destinations = [address(this)];

        uint256 taskId = registry.addTask(
            destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
        );
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        bytes4 selector = bytes4(keccak256(bytes("executeBatchEpoch(uint256,address[],uint256[],bytes[])")));
        values = [1 ether];
        datas = [new bytes(0)];
        bytes memory data = abi.encodeWithSelector(selector, taskId, destinations, values, datas);

        UserOperation memory userOp = UserOperation({
            sender: customAddress,
            nonce: 20,
            initCode: new bytes(0),
            callData: data,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: 1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        this.executeAsCallData(userOp);
        vm.prank(adEntrypoint);
        uint256 previousBalance = address(this).balance;
        wallet.executeBatchEpoch(taskId, destinations, values, datas);
        uint256 balancePostExecution = address(this).balance;
        assertEq(previousBalance + 1 ether, balancePostExecution);
    }

    function testValidateAndProcessTransaction() external {
        // initializing task
        address destination = address(this);
        bool isBatchTransaction = false;
        IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
            useExecutionWindow: true,
            recurring: true,
            recurrenceGap: 10000,
            executionWindowStart: 0,
            executionWindowEnd: 100000000
        });
        IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
            useOnChainCondition: false,
            conditionChecker: IConditionChecker(address(0)),
            dataPosition: 0,
            dataSource: address(0),
            dataType: IEpochRegistry.DataType.STRING,
            encodedQuery: new bytes(0),
            encodedCondition: new bytes(0)
        });
        IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
            useDataSource: false,
            dataPosition: 0,
            positionInCallData: 0,
            dataSource: address(0),
            encodedQuery: new bytes(0)
        });

        vm.prank(address(wallet));

        uint256 taskId = registry.addTask(
            destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
        );
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        bytes4 selector = bytes4(keccak256(bytes("executeEpoch(uint256,address,uint256,bytes)")));

        bytes memory data = abi.encodeWithSelector(selector, taskId, address(this), 1 ether, new bytes(0));
        UserOperation memory userOp = UserOperation({
            sender: customAddress,
            nonce: 20,
            initCode: new bytes(0),
            callData: data,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: 1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        this.executeAsCallData(userOp);
        vm.prank(adEntrypoint);
        uint256 previousBalance = address(this).balance;
        wallet.executeEpoch(taskId, destination, 1 ether, new bytes(0));
        uint256 balancePostExecution = address(this).balance;
        assertEq(previousBalance + 1 ether, balancePostExecution);
    }

    function testValidateAndProcessTransactioWithOnChainCondition() external {
        // initializing task
        uint256 taskId;
        address destination = address(this);
        {
            bool isBatchTransaction = false;
            IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
                useExecutionWindow: false,
                recurring: true,
                recurrenceGap: 10000,
                executionWindowStart: 0,
                executionWindowEnd: 100000000
            });
            EqualityChecker equalityChecker = new EqualityChecker();
            DummyData testUtil = new DummyData();
            bytes4 functionSig = bytes4(keccak256(bytes("returnDummyData()")));
            bytes memory encodedQuery = abi.encodeWithSelector(functionSig);
            IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
                useOnChainCondition: true,
                conditionChecker: IConditionChecker(address(equalityChecker)),
                dataPosition: 0,
                dataSource: address(testUtil),
                dataType: IEpochRegistry.DataType.UINT,
                encodedQuery: encodedQuery,
                encodedCondition: new bytes(0)
            });
            IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
                useDataSource: false,
                dataPosition: 0,
                positionInCallData: 0,
                dataSource: address(0),
                encodedQuery: new bytes(0)
            });

            vm.prank(address(wallet));

            taskId = registry.addTask(
                destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
            );
        }
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        bytes4 selector = bytes4(keccak256(bytes("executeEpoch(uint256,address,uint256,bytes)")));
        bytes memory data = abi.encodeWithSelector(selector, taskId, address(this), 1 ether, new bytes(0));
        UserOperation memory userOp = UserOperation({
            sender: customAddress,
            nonce: 20,
            initCode: new bytes(0),
            callData: data,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: 1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        {
            this.executeAsCallData(userOp);
            vm.prank(adEntrypoint);
            uint256 previousBalance = address(this).balance;
            wallet.executeEpoch(taskId, destination, 1 ether, new bytes(0));
            uint256 balancePostExecution = address(this).balance;
            assertEq(previousBalance + 1 ether, balancePostExecution);
        }
    }

    function testValidateAndProcessTransactioWithOnChainDataSource() external {
        // initializing task
        uint256 taskId;
        address destination = address(this);
        {
            bool isBatchTransaction = false;
            IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
                useExecutionWindow: false,
                recurring: true,
                recurrenceGap: 10000,
                executionWindowStart: 0,
                executionWindowEnd: 100000000
            });
            EqualityChecker equalityChecker = new EqualityChecker();
            DummyData testUtil = new DummyData();
            bytes4 functionSig = bytes4(keccak256(bytes("returnDummyData()")));
            bytes memory encodedQuery = abi.encodeWithSelector(functionSig);
            IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
                useOnChainCondition: true,
                conditionChecker: IConditionChecker(address(equalityChecker)),
                dataPosition: 0,
                dataSource: address(testUtil),
                dataType: IEpochRegistry.DataType.UINT,
                encodedQuery: encodedQuery,
                encodedCondition: new bytes(0)
            });

            IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
                useDataSource: true,
                dataPosition: 0,
                positionInCallData: 1,
                dataSource: address(testUtil),
                encodedQuery: encodedQuery
            });

            vm.prank(address(wallet));

            taskId = registry.addTask(
                destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
            );
        }
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        bytes4 selector = bytes4(keccak256(bytes("executeEpoch(uint256,address,uint256,bytes)")));
        bytes4 selectorDummyCall = bytes4(keccak256(bytes("dummyCall(uint256,uint256)")));

        bytes memory dummyCallData = abi.encodeWithSelector(selectorDummyCall, taskId, 69);
        bytes memory data = abi.encodeWithSelector(selector, taskId, address(this), 0, dummyCallData);

        UserOperation memory userOp = UserOperation({
            sender: customAddress,
            nonce: 20,
            initCode: new bytes(0),
            callData: data,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: 1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        {
            this.executeAsCallData(userOp);
            vm.prank(adEntrypoint);
            wallet.executeEpoch(taskId, address(this), 0, dummyCallData);
        }
        assertEq(gotTestCall[taskId], 1);
    }

    function testFailValidateAndProcessBatchTransactioWithOnChainDataSource() external {
        // initializing task
        uint256 taskId;
        address destination = address(this);
        {
            bool isBatchTransaction = true;
            IEpochRegistry.ExecutionWindow memory executionWindowCondition = IEpochRegistry.ExecutionWindow({
                useExecutionWindow: false,
                recurring: true,
                recurrenceGap: 10000,
                executionWindowStart: 0,
                executionWindowEnd: 100000000
            });
            EqualityChecker equalityChecker = new EqualityChecker();
            DummyData testUtil = new DummyData();
            bytes4 functionSig = bytes4(keccak256(bytes("returnDummyData()")));
            bytes memory encodedQuery = abi.encodeWithSelector(functionSig);
            IEpochRegistry.OnChainCondition memory onChainCondition = IEpochRegistry.OnChainCondition({
                useOnChainCondition: true,
                conditionChecker: IConditionChecker(address(equalityChecker)),
                dataPosition: 0,
                dataSource: address(testUtil),
                dataType: IEpochRegistry.DataType.UINT,
                encodedQuery: encodedQuery,
                encodedCondition: new bytes(0)
            });

            IEpochRegistry.DataSource memory dataSource = IEpochRegistry.DataSource({
                useDataSource: true,
                dataPosition: 0,
                positionInCallData: 1,
                dataSource: address(testUtil),
                encodedQuery: encodedQuery
            });

            vm.prank(address(wallet));

            taskId = registry.addTask(
                destination, isBatchTransaction, executionWindowCondition, onChainCondition, dataSource, destinations
            );
        }
    }

    function testFailProcessTransaction() external {
        vm.prank(adEntrypoint);
        wallet.executeEpoch(1, address(this), 1 ether, new bytes(0));
    }

    function testFailProcessBatchTransaction() external {
        vm.prank(adEntrypoint);
        destinations.push(address(this));
        values.push(1 ether);
        datas.push(new bytes(0));
        wallet.executeBatchEpoch(1, destinations, values, datas);
    }

    function executeAsCallData(UserOperation calldata userOp) external {
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 actualGasPrice = tx.gasprice;
        bytes32 userOpHash = userOp.hashWithoutNonce();
        UserOperation memory userOpAsMemory = userOp;
        bytes32 messageToSign = userOpHash.toEthSignedMessageHash();
        // bytes32 userOpMessageHash = userOpHash.toEthSignedMessageHash(); // correct hash

        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKey,
                //passing wrong hash, should have passed userOpMessageHash
                messageToSign
            );
            userOpAsMemory.signature = abi.encodePacked(r, s, v);
        }
        uint256 expectedPay = actualGasPrice * (callGasLimit + verificationGasLimit);
        vm.prank(adEntrypoint);
        uint256 validation = wallet.validateUserOp(userOpAsMemory, userOpHash, expectedPay);
        // uint256 previousBalance = address(this).balance;
        // (bool status,) = address(wallet).call(userOp.callData);
        // uint256 balancePostExecution = address(this).balance;
        // assertEq(status, true);
        // assertEq(previousBalance + 1 ether - expectedPay, balancePostExecution);
        assertEq(validation, 0);
    }
}
