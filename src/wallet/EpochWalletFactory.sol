// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "openzeppelin/utils/Create2.sol";
import "openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

import "./EpochWallet.sol";
import "openzeppelin/access/Ownable.sol";

/**
 * A sample factory contract for SimpleAccount
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract EpochWalletFactory is Ownable {
    EpochWallet public immutable accountImplementation;
    IEpochRegistry public epochRegistry;

    constructor(IEntryPoint _entryPoint, IEpochRegistry _epochRegistry) {
        accountImplementation = new EpochWallet(_entryPoint);
        epochRegistry = _epochRegistry;
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        address owner,
        uint256 salt
    ) public returns (EpochWallet ret) {
        address addr = getAddress(owner, salt);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return EpochWallet(payable(addr));
        }
        ret = EpochWallet(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(accountImplementation),
                    abi.encodeCall(
                        EpochWallet.initialize,
                        (owner, epochRegistry)
                    )
                )
            )
        );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(
        address owner,
        uint256 salt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                bytes32(salt),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(
                                EpochWallet.initialize,
                                (owner, epochRegistry)
                            )
                        )
                    )
                )
            );
    }

    function updateRegistry(IEpochRegistry _registry) external onlyOwner {
        require(
            address(_registry) != address(0),
            "Factory: Address must be valid"
        );
        epochRegistry = _registry;
    }
}
