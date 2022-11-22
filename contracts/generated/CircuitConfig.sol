
// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;
contract CircuitConfig {
  function _getCircuitConfig (uint256 blockGasLimit) internal pure returns (uint256, uint256) {
    
    if (blockGasLimit <= 63000) {
      return (3, 10500);
    }
    
    if (blockGasLimit <= 150000) {
      return (7, 32250);
    }
    
    if (blockGasLimit <= 300000) {
      return (14, 69750);
    }
    
    revert("CIRCUIT_CONFIG");
  }
}