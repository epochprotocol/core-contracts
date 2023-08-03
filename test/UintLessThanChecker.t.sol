// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../src/registry/conditions/UintLessThanChecker.sol";
import "forge-std/Test.sol";

contract UintLessThanConditionCheckerTest is Test {
    function testPassing() external {
        UintLessThanEqualToConditionChecker uintLessThanEqualToConditionChecker =
            new UintLessThanEqualToConditionChecker();
        bool resp = uintLessThanEqualToConditionChecker.checkCondition(abi.encode(2), abi.encode(1));
        assertEq(resp, true);
    }

    function testNotPassing() external {
        UintLessThanEqualToConditionChecker uintLessThanEqualToConditionChecker =
            new UintLessThanEqualToConditionChecker();
        bool resp = uintLessThanEqualToConditionChecker.checkCondition(abi.encode(2), abi.encode(4));
        assertEq(resp, false);
    }

    function testEqual() external {
        UintLessThanEqualToConditionChecker uintLessThanEqualToConditionChecker =
            new UintLessThanEqualToConditionChecker();
        bool resp = uintLessThanEqualToConditionChecker.checkCondition(abi.encode(2), abi.encode(2));
        assertEq(resp, true);
    }
}
