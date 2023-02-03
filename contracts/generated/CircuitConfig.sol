
// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;
contract CircuitConfig {
  function _getCircuitConfig (uint256 blockGasLimit) internal pure returns (uint256, uint256) {
    
    if (blockGasLimit <= 63000) {
      return (3, 10500);
    }
    
    if (blockGasLimit <= 300000) {
      return (14, 69750);
    }
    
    revert("CIRCUIT_CONFIG");
  }
}