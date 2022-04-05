// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';
import './ZkEvmMessageDispatcher.sol';
import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './PatriciaValidator.sol';

contract ZkEvmL1Bridge is
  ZkEvmUtils,
  ZkEvmMagicNumbers,
  ZkEvmBridgeEvents,
  ZkEvmMessageDispatcher,
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDelivererWithProof,
  PatriciaValidator
{
  bytes32 public safeBlockHash;
  bytes32 public finalizedBlockHash;
  bytes32 public stateRoot;

  function submitBlock (bytes calldata _data) external {
    _onlyEOA();

    safeBlockHash = keccak256(_data);

    emit BlockSubmitted();
  }

  function finalizeBlock (bytes32 blockHash, bytes calldata _witness, bytes calldata _proof) external {
    finalizedBlockHash = blockHash;
    assembly {
      let stateRootOffset := add(_witness.offset, 91)
      let val := calldataload(stateRootOffset)
      sstore(stateRoot.slot, val)
    }

    emit BlockFinalized(blockHash);
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

    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
    (bytes32 proofRoot, bytes32 storageValue) = _validatePatriciaProof(
      L2_DISPATCHER,
      _PENDING_MESSAGE_KEY(messageHash),
      proof
    );
    require(proofRoot == stateRoot, 'DMROOT');
    require(storageValue == bytes32(uint256(1)), "DMVAL");

    _deliverMessage(from, to, value, fee, deadline, nonce, data);
  }
}
