// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.12;

/**
 * keccak function over calldata.
 * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
 */
function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}
