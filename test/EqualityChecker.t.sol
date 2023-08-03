// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../src/registry/conditions/EqualityChecker.sol";
import "forge-std/Test.sol";

contract EqualityCheckerTest is Test {
    function testEquality() external {
        EqualityChecker equalityChecker = new EqualityChecker();
        bool resp = equalityChecker.checkCondition(abi.encode(1), abi.encode(1));
        assertEq(resp, true);
    }

    function testUnequality() external {
        EqualityChecker equalityChecker = new EqualityChecker();
        bool resp = equalityChecker.checkCondition(abi.encode(1), abi.encode("q"));
        assertEq(resp, false);
    }
}
