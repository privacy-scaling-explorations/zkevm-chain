// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

interface IZkEvmMessageDelivererBase {
  /// @notice Returns the address of the caller that dispatched the message.
  function messageOrigin () external view returns (address);
}
