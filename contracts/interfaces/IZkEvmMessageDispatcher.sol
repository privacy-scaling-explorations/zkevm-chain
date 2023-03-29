// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

interface IZkEvmMessageDispatcher {
  /// @notice Dispatch a message to the opposite chain.
  /// @param to The address of the account/contract to call and transfer `msg.value - fee`.
  /// @param fee Amount to be paid to the account that delivers this message on the destination chain. Deducted from `msg.value`.
  /// @param deadline This message is valid **before** the deadline and can be dropped **after** the deadline. In seconds since Unix Epoch.
  /// @param nonce A random value that can be used to avoid collisions for identical but distinct messages. Has no other purpose.
  /// @param data The calldata to be used when calling `to`.
  /// @return messageHash `keccak256(abi.encode(msg.sender, to, value, fee, deadline, nonce, data))`.
  /// Please note that only one message with the same hash can be dispatched at the same time.
  /// A message hash is not unique in the sense that it can reappear once a previous message was delivered or dropped.
  function dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external payable returns (bytes32 messageHash);

  /// @notice Drops a expired message and returns ETH - if any to `from`.
  function dropMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data,
    bytes calldata proof
  ) external;
}
