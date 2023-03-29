// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './IZkEvmMessageDelivererBase.sol';

interface IZkEvmMessageDelivererWithProof is IZkEvmMessageDelivererBase {
  // TODO: move & refine this
  event ForeignBridgeStateImported(bytes32 indexed blockHash, bytes32 indexed stateRoot, uint256 timestamp);

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

  function getTimestampForStorageRoot (bytes32 storageRootHash) external view returns (uint256);

  function importForeignBridgeState (bytes calldata blockHeader, bytes calldata accountProof) external;
}
