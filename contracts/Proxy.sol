// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

/// @notice Callforwarding proxy
contract Proxy {
  constructor (address initialImplementation) {
    assembly {
      // stores the initial contract address to forward calls
      sstore(not(returndatasize()), initialImplementation)
    }
  }

  fallback () external payable {
    assembly {
      // copy all calldata into memory - returndatasize() is a substitute for `0`
      calldatacopy(returndatasize(), returndatasize(), calldatasize())
      // keep a copy to be used after the call
      let zero := returndatasize()
      // call contract address loaded from storage slot with key `uint256(-1)`
      let success := delegatecall(
        gas(),
        sload(not(returndatasize())),
        returndatasize(),
        calldatasize(),
        returndatasize(),
        returndatasize()
      )

      // copy all return data into memory
      returndatacopy(zero, zero, returndatasize())

      // if the delegatecall succeeded, then return
      if success {
        return(zero, returndatasize())
      }
      // else revert
      revert(zero, returndatasize())
    }
  }

  /// @notice For testing purposes only.
  function upgrade (address to) external {
    assembly {
      // stores the contract address to forward calls
      sstore(not(returndatasize()), to)
    }
  }
}
