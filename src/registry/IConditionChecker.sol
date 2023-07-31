// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

interface IConditionChecker {
    function checkCondition(bytes memory userInput, bytes memory onChainCondition) external returns (bool);
}
