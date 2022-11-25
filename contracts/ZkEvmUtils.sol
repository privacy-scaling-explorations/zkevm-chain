// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract ZkEvmUtils {
  /// @dev Revert if caller is not tx sender.
  function _onlyEOA () internal view {
    require(tx.origin == msg.sender, 'EOA');
  }

  function _transferETH (address receiver, uint256 amount) internal {
    (bool success,) = receiver.call{ value: amount }("");
    require(success, 'TETH');
  }

  function _callAccount (address to, uint256 value, bytes calldata data) internal {
    assembly {
      let ptr := 128
      calldatacopy(ptr, data.offset, data.length)
      if iszero(call(gas(), to, value, ptr, data.length, 0, 0)) {
        returndatacopy(0, 0, returndatasize())
        revert(0, returndatasize())
      }
    }
  }
}
