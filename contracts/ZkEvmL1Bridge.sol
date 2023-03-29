// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';
import './ZkEvmMessageDispatcherBase.sol';
import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDispatcher.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './generated/PatriciaAccountValidator.sol';
import './generated/PatriciaStorageValidator.sol';
import './generated/PublicInput.sol';
import './generated/HeaderUtil.sol';
import './generated/CircuitConfig.sol';
import './Multicall.sol';

contract ZkEvmL1Bridge is
  ZkEvmUtils,
  ZkEvmMagicNumbers,
  ZkEvmBridgeEvents,
  ZkEvmMessageDispatcherBase,
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDispatcher,
  IZkEvmMessageDelivererWithProof,
  PatriciaAccountValidator,
  PatriciaStorageValidator,
  PublicInput,
  HeaderUtil,
  CircuitConfig,
  Multicall
{
  // TODO: Move storage to static slots
  mapping (bytes32 => bytes32) commitments;
  mapping (bytes32 => bytes32) public stateRoots;
  mapping (bytes32 => uint256) originTimestamps;

  function buildCommitment(bytes calldata witness) public view returns (uint256[] memory result) {
    (
      bytes32 parentBlockHash,
      ,
      ,
      ,
      uint256 blockGas,
    ) = _readHeaderParts(witness);
    uint256 parentStateRoot = uint256(stateRoots[parentBlockHash]);
    uint256 chainId = 99;
    (uint256 MAX_TXS, uint256 MAX_CALLDATA) = _getCircuitConfig(blockGas);

    result = _buildCommitment(MAX_TXS, MAX_CALLDATA, chainId, parentStateRoot, witness, true);
  }

  function submitBlock (bytes calldata witness) external {
    _onlyEOA();
    emit BlockSubmitted();

    (
      bytes32 parentBlockHash,
      bytes32 blockHash,
      bytes32 blockStateRoot,
      ,
      uint256 blockGas,
    ) = _readHeaderParts(witness);
    uint256 parentStateRoot = uint256(stateRoots[parentBlockHash]);
    uint256 chainId = 99;
    (uint256 MAX_TXS, uint256 MAX_CALLDATA) = _getCircuitConfig(blockGas);

    uint256[] memory publicInput =
      _buildCommitment(MAX_TXS, MAX_CALLDATA, chainId, parentStateRoot, witness, true);

    bytes32 hash;
    assembly {
      hash := keccak256(add(publicInput, 32), mul(mload(publicInput), 32))
    }
    commitments[blockHash] = hash;
    stateRoots[blockHash] = blockStateRoot;
  }

  /// @dev
  /// proof layout (bytes)
  /// - block hash
  /// - verifier address (TODO: should be checked against allowed verifier addresses)
  /// - proof instance - first 5 elements commitment
  /// - proof transcript
  function finalizeBlock (bytes calldata proof) external {
    require(proof.length > 511, "PROOF_LEN");

    bytes32 blockHash;
    assembly {
      blockHash := calldataload(proof.offset)
    }
    bytes32 expectedCommitmentHash = commitments[blockHash];

    assembly {
      // function Error(string)
      function revertWith (msg) {
        mstore(0, shl(224, 0x08c379a0))
        mstore(4, 32)
        mstore(68, msg)
        let msgLen
        for {} msg {} {
          msg := shl(8, msg)
          msgLen := add(msgLen, 1)
        }
        mstore(36, msgLen)
        revert(0, 100)
      }

      // verify commitment hash
      {
          // 5 * 32
          let len := 160
          let ptr := mload(64)
          // skip `blockHash, address, is_aggregated`
          calldatacopy(ptr, add(proof.offset, 96), len)
          let hash := keccak256(ptr, len)
          if iszero(eq(hash, expectedCommitmentHash)) {
            revertWith("commitment hash")
          }
      }

      {
        // call contract at `addr` for proof verification
        let offset := add(proof.offset, 32)
        let addr := calldataload(offset)
        switch extcodesize(addr)
        case 0 {
          // no code at `addr`
          revertWith("verifier missing")
        }

        let len := sub(proof.length, 96)
        offset := add(offset, 64)
        let memPtr := mload(64)
        calldatacopy(memPtr, offset, len)
        let success := staticcall(gas(), addr, memPtr, len, 0, 0)
        switch success
        case 0 {
          // plonk verification failed
          //returndatacopy(0, 0, returndatasize())
          //revert(0, returndatasize())
          revertWith("verifier failed")
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
    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
    (bytes32 proofStorageRoot, bytes32 storageValue) = _validatePatriciaStorageProof(
      _PENDING_MESSAGE_KEY(messageHash),
      proof
    );
    require(originTimestamps[proofStorageRoot] != 0, 'DMROOT');
    require(storageValue == bytes32(uint256(1)), 'DMVAL');

    _deliverMessage(from, to, value, fee, deadline, nonce, data);
  }

  /// @inheritdoc IZkEvmMessageDelivererWithProof
  function getTimestampForStorageRoot (bytes32 val) public view returns (uint256) {
    return originTimestamps[val];
  }

  /// @inheritdoc IZkEvmMessageDelivererWithProof
  function importForeignBridgeState (bytes calldata blockHeader, bytes calldata accountProof) external {
    (
      ,
      bytes32 blockHash,
      ,
      ,
      ,
      uint256 timestamp
    ) = _readHeaderParts(blockHeader);

    (bytes32 proofStateRoot, bytes32 proofStorageRoot) = _validatePatriciaAccountProof(
      L2_DISPATCHER,
      accountProof
    );
    bytes32 stateRoot = stateRoots[blockHash];
    require(stateRoot != 0, 'BLOCK');
    require(proofStateRoot == stateRoot, 'IBROOT');
    require(proofStorageRoot != 0, 'IBSTROOT');
    require(timestamp != 0, 'IBTS');
    originTimestamps[proofStorageRoot] = timestamp;

    emit ForeignBridgeStateImported(blockHash, stateRoot, timestamp);
  }

  /// @inheritdoc IZkEvmMessageDispatcher
  function dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external payable returns (bytes32 messageHash) {
    messageHash = _dispatchMessage(to, fee, deadline, nonce, data);
  }

  /// @inheritdoc IZkEvmMessageDispatcher
  function dropMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data,
    bytes calldata proof
  ) external {
    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
    (bytes32 proofStorageRoot, bytes32 storageValue) = _validatePatriciaStorageProof(
      _PENDING_MESSAGE_KEY(messageHash),
      proof
    );
    require(storageValue == 0, 'DMVAL');
    uint256 originTimestamp = originTimestamps[proofStorageRoot];
    require(originTimestamp > deadline, 'DMTS');

    _dropMessage(from, to, value, fee, deadline, nonce, data);
  }

  /// @dev For testing purposes
  function initGenesis (bytes32 _blockHash, bytes32 _stateRoot) external {
    stateRoots[_blockHash] = _stateRoot;
  }
}
