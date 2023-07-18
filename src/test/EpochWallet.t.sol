// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "forge-std/Vm.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../registry/EpochRegistry.sol";
import "../wallet/EpochWallet.sol";
import "../wallet/EpochWalletFactory.sol";

contract EpochWalletTest is Test {
    EpochWallet public wallet;
    EpochWalletFactory public factory;

    uint256 public mainnetFork;
    address public immutable adEntrypoint =
        0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public immutable salt = 123456;

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
        console2.log(address(registry));
        IEntryPoint ept = IEntryPoint(adEntrypoint);
        factory = new EpochWalletFactory(ept, registry);
        wallet = factory.createAccount(address(this), salt);
        hoax(address(wallet), 100 ether);
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
        dests[0] = address(this);
        bytes[] memory funcs = new bytes[](1);
        funcs[0] = data;
        wallet.executeBatchEpoch(taskid, dests, funcs);
        assertEq(gotFallback[taskid], true);
    }
}
