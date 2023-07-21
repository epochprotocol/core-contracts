// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/registry/EpochRegistry.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "../src/wallet/EpochWalletFactory.sol";
import "../src/wallet/EpochWallet.sol";
import "openzeppelin/utils/Address.sol";

contract EpochWalletFactoryTest is Test {
    using Address for address;

    address public immutable adEntrypoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    EpochWalletFactory _factory;
    uint256 public immutable salt = 123456;

    constructor() {
        string memory mainnetUrl = vm.envString("MAINNET_RPC_URL");
        vm.createFork(mainnetUrl);
        EpochRegistry registry = new EpochRegistry();
        IEntryPoint ept = IEntryPoint(adEntrypoint);
        EpochWallet walletImpl = new EpochWallet(ept);
        _factory = new EpochWalletFactory(walletImpl, registry);
    }

    function testCreateWallet() public {
        address owner = msg.sender;

        EpochWallet wallet = _factory.createAccount(owner, salt);

        assertEq(address(wallet).isContract(), true);
    }
}
