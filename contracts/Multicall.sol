// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract Multicall {
  /// @notice Used to repeatly call to self.
  /// Expects [length of bytes (4 bytes), bytes, ...] appended directly after the function signature.
  /// Reverts as soon a call fails.
  function multicall () external {
    assembly {
      // starts after function signature (4 bytes)
      for { let ptr := 4 } lt(ptr, calldatasize()) {} {
        let len := shr(224, calldataload(ptr))
        ptr := add(ptr, 4)
        calldatacopy(0, ptr, len)
        ptr := add(ptr, len)
        let success := call(gas(), address(), 0, 0, len, 0, 0)
        switch success
        case 0 {
          returndatacopy(0, 0, returndatasize())
          revert(0, returndatasize())
        }
      }

      stop()
    }
  }
}
