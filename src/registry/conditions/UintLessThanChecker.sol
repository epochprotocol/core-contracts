// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../IConditionChecker.sol";

contract UintLessThanEqualToConditionChecker is IConditionChecker {
    function checkCondition(bytes memory userInput, bytes memory onChainCondition) external pure returns (bool) {
        (uint256 _userInput) = abi.decode(userInput, (uint256));
        (uint256 _onChainCondition) = abi.decode(onChainCondition, (uint256));
        return _onChainCondition <= _userInput;
    }
}
