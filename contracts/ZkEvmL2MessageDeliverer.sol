// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './generated/PatriciaAccountValidator.sol';
import './generated/PatriciaStorageValidator.sol';
import './ZkEvmStorage.sol';
import './generated/CommonBlockOperations.sol';

contract ZkEvmL2MessageDeliverer is
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDelivererWithProof,
  ZkEvmStorage,
  PatriciaAccountValidator,
  PatriciaStorageValidator,
  CommonBlockOperations
{
  // TODO: decide on public getters once L1/L2 Inbox is DRY
  // Latest known L1 block hash
  bytes32 lastKnownL1BlockHash;
  // Mapping from <storage root of L1 bridge> to L1 block timestamp
  mapping (bytes32 => uint256) storageRootToTimestamp;

  /// @inheritdoc IZkEvmMessageDelivererWithProof
  function getTimestampForStorageRoot (bytes32 val) public view returns (uint256) {
    return storageRootToTimestamp[val];
  }

  /// @dev `blockNumber` & `blockHash` must be checked by the L1 verification step(s).
  function importForeignBlock (
    uint256 /*blockNumber*/,
    bytes32 blockHash
  ) external {
    _onlyEOA();
    // should be restricted to block producer set
    // require(msg.sender == block.coinbase, 'IBH');
    lastKnownL1BlockHash = blockHash;
  }

  /// @inheritdoc IZkEvmMessageDelivererWithProof
  function importForeignBridgeState (bytes calldata blockHeader, bytes calldata accountProof) external {
    (bytes32 hash, bytes32 stateRoot, uint256 timestamp) = _readBlockHeader(blockHeader);
    require(hash == lastKnownL1BlockHash, 'HASH');

    (bytes32 proofStateRoot, bytes32 proofStorageRoot) = _validatePatriciaAccountProof(
      L1_BRIDGE,
      accountProof
    );
    require(proofStateRoot == stateRoot, 'DMROOT');
    storageRootToTimestamp[proofStorageRoot] = timestamp;

    emit ForeignBridgeStateImported(hash, stateRoot, timestamp);
  }

  /// @inheritdoc IZkEvmMessageDelivererWithProof
  function deliverMessageWithProof (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data,
    bytes calldata storageProof
  ) external {
    // avoid calling the 'requestETH' or any other 'administrative' functions from L2_DELIVERER
    require(to != L2_DISPATCHER, 'TNED');

    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
    (bytes32 storageRoot, bytes32 storageValue) = _validatePatriciaStorageProof(
      _PENDING_MESSAGE_KEY(messageHash),
      storageProof
    );
    uint256 originTimestamp = storageRootToTimestamp[storageRoot];
    require(originTimestamp != 0, 'STROOT');
    require(originTimestamp < deadline, 'DMTS');
    require(storageValue == bytes32(uint256(1)), 'DMVAL');

    _deliverMessage(from, to, value, fee, deadline, nonce, data);
  }

  function requestETH (uint256 amount) external {
    require(msg.sender == L2_DISPATCHER, 'MSEDS');

    _transferETH(msg.sender, amount);
  }

  receive () external payable {
    require(msg.sender == L2_DISPATCHER, 'MSEDS');
  }
}
