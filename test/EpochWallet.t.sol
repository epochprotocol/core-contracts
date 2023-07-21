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

contract EpochWalletTest is Test {
    using UserOperationLib for UserOperation;
    using ECDSA for bytes32;
    EpochWallet public wallet;
    EpochWalletFactory public factory;

    uint256 public mainnetFork;
    address public immutable adEntrypoint =
        0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public immutable salt = 123456;

    address private immutable deployer =
        0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84;
    string mnemonic;
    uint256 privateKey;
    mapping(uint256 => bool) gotFallback;

    receive() external payable {}

    fallback() external payable {
        uint256 data = abi.decode(msg.data, (uint256));
        gotFallback[data] = true;
    }

    constructor() {
        string memory mainnetUrl = vm.envString("MAINNET_RPC_URL");
        mainnetFork = vm.createFork(mainnetUrl);
        EpochRegistry registry = new EpochRegistry();
        IEntryPoint ept = IEntryPoint(adEntrypoint);
        factory = new EpochWalletFactory(ept, registry);
        wallet = factory.createAccount(address(this), salt);
        hoax(address(wallet), 100 ether);

        mnemonic = vm.envString("TEST_MNEMONIC");
        privateKey = vm.deriveKey(mnemonic, 0);
    }

    function testExecuteEpoch() public {
        bytes memory data = new bytes(0);
        wallet.executeEpoch(1, address(this), 1 ether, data);
        assertEq(address(wallet).balance, 99 ether);
    }

    function testExecuteEpochBatch() public {
        uint256 taskid = 1;
        bytes memory data = abi.encode(taskid);
        address[] memory dests = new address[](1);
        uint256[] memory values = new uint256[](1);
        values[0] = 1 ether;
        dests[0] = address(this);
        bytes[] memory funcs = new bytes[](1);
        funcs[0] = data;
        wallet.executeBatchEpoch(taskid, dests, values, funcs);
        assertEq(gotFallback[taskid], true);
    }

    function testTransfer() public {
        bytes memory data = new bytes(0);
        wallet.execute(address(this), 1 ether, data);
        assertEq(address(wallet).balance, 99 ether);
    }

    function testCannotTransfer() public {
        vm.expectRevert("account: not Owner or EntryPoint");
        bytes memory data = new bytes(0);
        vm.prank(address(0));
        wallet.execute(address(this), 1 ether, data);
    }

    function testValidateUserOp() public {
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        uint256 actualGasPrice = tx.gasprice;
        // uint256 taskid = 1;
        address testUser = vm.addr(privateKey);

        bytes4 selector = bytes4(
            keccak256(
                bytes(
                    "execute(address dest, uint256 value, bytes calldata func)"
                )
            )
        );
        bytes memory data = abi.encodeWithSelector(
            selector,
            testUser,
            1 ether,
            new bytes(0)
        );
        // bytes memory data = abi.encode(taskid);

        // vm.prank(testUser);
        hoax(testUser, 100 ether);

        EpochWallet testWallet = factory.createAccount(testUser, salt);
        UserOperation memory userOp = UserOperation({
            sender: address(this),
            nonce: 0,
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

        TestUtil testUtil = new TestUtil();

        bytes memory returnData = testUtil.packUserOp(userOp);

        bytes32 userOpHash = keccak256(returnData);
        bytes32 userOpMessageHash = userOpHash.toEthSignedMessageHash();

        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKey,
                userOpMessageHash
            );
            userOp.signature = abi.encodePacked(r, s, v);
        }

        uint256 expectedPay = actualGasPrice *
            (callGasLimit + verificationGasLimit);

        // vm.stopPrank();
        vm.prank(adEntrypoint);
        // hoax(adEntrypoint, 100 ether);
        uint256 preBalance = address(testWallet).balance;

        uint256 validation = testWallet.validateUserOp(
            userOp,
            userOpHash,
            expectedPay
        );
        assertEq(validation, 0);
        uint256 postBalance = address(testWallet).balance;

        assertEq(preBalance - postBalance, expectedPay);
    }

    function testExecuteEpochAlteredNonce() public {
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        uint256 actualGasPrice = tx.gasprice;
        // uint256 taskid = 1;
        address testUser = vm.addr(privateKey);

        bytes4 selector = bytes4(
            keccak256(
                bytes(
                    "executeEpoch(uint256 taskId, address dest, uint256 value, bytes calldata func)"
                )
            )
        );
        bytes memory data = abi.encodeWithSelector(
            selector,
            1,
            testUser,
            1 ether,
            new bytes(0)
        );

        // bytes memory data = abi.encode(taskid);

        // vm.prank(testUser);
        hoax(testUser, 100 ether);

        EpochWallet testWallet = factory.createAccount(testUser, salt);
        UserOperation memory userOp = UserOperation({
            sender: address(this),
            nonce: 4,
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

        TestUtil testUtil = new TestUtil();

        bytes memory returnData = testUtil.packUserOp(userOp);

        bytes32 userOpHash = keccak256(returnData);
        bytes32 userOpMessageHash = userOpHash.toEthSignedMessageHash();

        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKey,
                userOpMessageHash
            );
            userOp.signature = abi.encodePacked(r, s, v);
        }

        uint256 expectedPay = actualGasPrice *
            (callGasLimit + verificationGasLimit);

        // vm.stopPrank();
        vm.prank(adEntrypoint);
        // hoax(adEntrypoint, 100 ether);
        uint256 preBalance = address(testWallet).balance;

        uint256 validation = testWallet.validateUserOp(
            userOp,
            userOpHash,
            expectedPay
        );
        assertEq(validation, 0);
        uint256 postBalance = address(testWallet).balance;

        assertEq(preBalance - postBalance, expectedPay);
    }

    function testBatchExecuteEpochAlteredNonce() public {
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        uint256 actualGasPrice = tx.gasprice;
        // uint256 taskid = 1;
        address testUser = vm.addr(privateKey);

        bytes4 selector = bytes4(
            keccak256(
                bytes(
                    "executeBatchEpoch( uint256 taskId, address[] calldata dest, uint256[] calldata value, bytes[] calldata func)"
                )
            )
        );
        bytes memory data = abi.encodeWithSelector(
            selector,
            1,
            [testUser],
            [1 ether],
            [new bytes(0)]
        );

        // bytes memory data = abi.encode(taskid);

        // vm.prank(testUser);
        hoax(testUser, 100 ether);

        EpochWallet testWallet = factory.createAccount(testUser, salt);
        UserOperation memory userOp = UserOperation({
            sender: address(this),
            nonce: 4,
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

        TestUtil testUtil = new TestUtil();

        bytes memory returnData = testUtil.packUserOp(userOp);

        bytes32 userOpHash = keccak256(returnData);
        bytes32 userOpMessageHash = userOpHash.toEthSignedMessageHash();

        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKey,
                userOpMessageHash
            );
            userOp.signature = abi.encodePacked(r, s, v);
        }

        uint256 expectedPay = actualGasPrice *
            (callGasLimit + verificationGasLimit);

        // vm.stopPrank();
        vm.prank(adEntrypoint);
        // hoax(adEntrypoint, 100 ether);
        uint256 preBalance = address(testWallet).balance;

        uint256 validation = testWallet.validateUserOp(
            userOp,
            userOpHash,
            expectedPay
        );
        assertEq(validation, 0);
        uint256 postBalance = address(testWallet).balance;

        assertEq(preBalance - postBalance, expectedPay);
    }

    function testValidateUserOpInvalidSignature() public {
        uint256 callGasLimit = 200000;
        uint256 verificationGasLimit = 100000;
        uint256 preVerificationGas = 100000;
        uint256 actualGasPrice = tx.gasprice;
        // uint256 taskid = 1;
        address testUser = vm.addr(privateKey);

        bytes4 selector = bytes4(
            keccak256(
                bytes(
                    "execute(address dest, uint256 value, bytes calldata func)"
                )
            )
        );
        bytes memory data = abi.encodeWithSelector(
            selector,
            testUser,
            1 ether,
            new bytes(0)
        );

        // bytes memory data = abi.encode(taskid);

        // vm.prank(testUser);
        hoax(testUser, 100 ether);

        EpochWallet testWallet = factory.createAccount(testUser, salt);
        UserOperation memory userOp = UserOperation({
            sender: address(this),
            nonce: 0,
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

        TestUtil testUtil = new TestUtil();

        bytes memory returnData = testUtil.packUserOp(userOp);

        bytes32 userOpHash = keccak256(returnData);
        // bytes32 userOpMessageHash = userOpHash.toEthSignedMessageHash(); // correct hash

        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKey,
                //passing wrong hash, should have passed userOpMessageHash
                userOpHash
            );
            userOp.signature = abi.encodePacked(r, s, v);
        }

        uint256 expectedPay = actualGasPrice *
            (callGasLimit + verificationGasLimit);

        // vm.stopPrank();
        vm.prank(adEntrypoint);
        // hoax(adEntrypoint, 100 ether);

        uint256 validation = testWallet.validateUserOp(
            userOp,
            userOpHash,
            expectedPay
        );
        assertEq(validation, 1);
    }
}
