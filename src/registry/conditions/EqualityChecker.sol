// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../IConditionChecker.sol";

contract EqualityChecker is IConditionChecker {
    function checkCondition(bytes memory userInput, bytes memory onChainCondition) external returns (bool) {
        return true;
    }
}
