// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';
import './ZkEvmMessageDispatcher.sol';
import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './generated/PatriciaValidator.sol';

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

  function finalizeBlock (bytes32 blockHash, bytes calldata _witness, bytes calldata proof) external {
    finalizedBlockHash = blockHash;
    assembly {
      let stateRootOffset := add(_witness.offset, 91)
      let val := calldataload(stateRootOffset)
      sstore(stateRoot.slot, val)

      if gt(proof.length, 32) {
        // call contract at `addr` for proof verification
        let offset := proof.offset
        let addr := calldataload(offset)
        switch extcodesize(addr)
        case 0 {
          // no code at `addr`
          revert(0, 1)
        }

        let len := sub(proof.length, 32)
        offset := add(offset, 32)
        let memPtr := mload(64)
        calldatacopy(memPtr, offset, len)
        let success := staticcall(gas(), addr, memPtr, len, 0, 0)
        switch success
        case 0 {
          // plonk verification failed
          returndatacopy(0, 0, returndatasize())
          revert(0, returndatasize())
        }
      }
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
