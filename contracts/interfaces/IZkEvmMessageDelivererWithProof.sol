// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './IZkEvmMessageDelivererBase.sol';

interface IZkEvmMessageDelivererWithProof is IZkEvmMessageDelivererBase {
  /// @notice Verifies the proof and executes the message.
  function deliverMessageWithProof (
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
