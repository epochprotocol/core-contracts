// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../src/registry/conditions/UintGreaterThanChecker.sol";
import "forge-std/Test.sol";

contract UintGreaterThanConditionCheckerTest is Test {
    function testPassing() external {
        UintGreaterThanEqualToConditionChecker greaterThanChecker = new UintGreaterThanEqualToConditionChecker();
        bool resp = greaterThanChecker.checkCondition(abi.encode(1), abi.encode(2));
        assertEq(resp, true);
    }

    function testNotPassing() external {
        UintGreaterThanEqualToConditionChecker greaterThanChecker = new UintGreaterThanEqualToConditionChecker();
        bool resp = greaterThanChecker.checkCondition(abi.encode(4), abi.encode(2));
        assertEq(resp, false);
    }

    function testEqual() external {
        UintGreaterThanEqualToConditionChecker greaterThanChecker = new UintGreaterThanEqualToConditionChecker();
        bool resp = greaterThanChecker.checkCondition(abi.encode(2), abi.encode(2));
        assertEq(resp, true);
    }
}
