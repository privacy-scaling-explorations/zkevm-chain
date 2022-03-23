// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

interface IZkEvmMessageDispatcher {
  /// @notice Dispatch a message.
  function dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external payable returns (bytes32 messageHash);

  /// @notice Drops a expired message and returns ETH - if any.
  function dropMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external;
}
