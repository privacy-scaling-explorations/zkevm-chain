// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './generated/PatriciaValidator.sol';
import './ZkEvmStorage.sol';
import './generated/CommonBlockOperations.sol';

contract ZkEvmL2MessageDeliverer is
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDelivererWithProof,
  ZkEvmStorage,
  PatriciaValidator,
  CommonBlockOperations
{
  // TODO: decide on public getters once L1/L2 Inbox is DRY
  // state root of L1
  bytes32 originStateRoot;
  // timestamp of L1
  uint256 originTimestamp;

  /// @notice This method imports [stateRoot, timestamp] of a block header.
  /// `blockNumber` & `blockHash` must be checked by the L1 verification step(s).
  function importBlockHeader (uint256 /*blockNumber*/, bytes32 blockHash, bytes calldata blockHeader) external {
    (bytes32 hash, bytes32 stateRoot, uint256 timestamp) = _readBlockHeader(blockHeader);
    require(hash == blockHash, 'HASH');

    originStateRoot = stateRoot;
    originTimestamp = timestamp;
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
    bytes calldata proof
  ) external {
    _onlyEOA();
    // avoid calling the 'requestETH' or any other 'administrative' functions from L2_DELIVERER
    require(to != L2_DISPATCHER, 'TNED');

    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
    (bytes32 proofRoot, bytes32 storageValue) = _validatePatriciaProof(
      L1_BRIDGE,
      _PENDING_MESSAGE_KEY(messageHash),
      proof
    );
    require(proofRoot == originStateRoot, 'DMROOT');
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
