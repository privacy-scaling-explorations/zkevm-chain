// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

/// @notice Holds common functions for storage key calculations.
contract ZkEvmStorage {
   function _PENDING_MESSAGE_KEY (bytes32 messageId) internal pure returns (bytes32 ret) {
    assembly {
      mstore(0, 0x31df76a4)
      mstore(32, messageId)
      ret := keccak256(0, 64)
    }
  }
}
