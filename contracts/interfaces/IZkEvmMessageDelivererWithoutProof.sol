// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './IZkEvmMessageDelivererBase.sol';

interface IZkEvmMessageDelivererWithoutProof is IZkEvmMessageDelivererBase {
  /// @notice Verifies and executes the message.
  function deliverMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external;
}
