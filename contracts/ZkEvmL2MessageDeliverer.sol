// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './generated/PatriciaValidator.sol';
import './ZkEvmStorage.sol';

contract ZkEvmL2MessageDeliverer is
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDelivererWithProof,
  ZkEvmStorage,
  PatriciaValidator
{
  // TODO: decide on public getters once L1/L2 Inbox is DRY
  // state root of L1
  bytes32 originStateRoot;
  // timestamp of L1
  uint256 originTimestamp;

  /// @notice This method imports [stateRoot, timestamp] of a block header.
  /// `blockNumber` & `blockHash` must be checked by the L1 verification step(s).
  function importBlockHeader (uint256 /*blockNumber*/, bytes32 blockHash, bytes calldata blockHeader) external {
    assembly {
      // TODO: use templating techniques and DRY code (with PatriciaValidator).

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

      // loads and aligns a value from calldata
      // given the `len|offset` stored at `memPtr`
      function loadValue (memPtr) -> value, len {
        let tmp := mload(memPtr)
        // assuming 0xffffff is sufficient for storing calldata offset
        let offset := and(tmp, 0xffffff)
        len := shr(128, tmp)

        if gt(len, 31) {
          // special case - truncating the value is intended.
          // this matches the behavior in `derivePath` that truncates to 256 bits.
          offset := add(offset, sub(len, 32))
          value := calldataload(offset)
          leave
        }

        // everything else is
        // < 32 bytes - align the value
        let bits := mul( sub(32, len), 8)
        value := calldataload(offset)
        value := shr(bits, value)
      }

      // returns the `len` of the whole RLP list at `ptr`
      // and the offset for the first value inside the list.
      function decodeListLength (ptr) -> len, startOffset {
        let firstByte := byte(0, calldataload(ptr))

        // SHORT LIST
        // 0 - 55 bytes
        // 0xc0 - 0xf7
        if lt(firstByte, 0xf8) {
          len := sub(firstByte, 0xbf)
          startOffset := add(ptr, 1)
          leave
        }

        // LONG LIST
        // 0xf8 - 0xff
        // > 55 bytes
        {
          let lenOf := sub(firstByte, 0xf7)

          // load the extended length
          startOffset := add(ptr, 1)
          let extendedLen := calldataload(startOffset)
          let bits := sub(256, mul(lenOf, 8))
          extendedLen := shr(bits, extendedLen)

          len := add(extendedLen, lenOf)
          len := add(len, 1)
          startOffset := add(startOffset, lenOf)
          leave
        }
      }

      // returns the calldata offset of the value and the length in bytes
      // for the RLP encoded data item at `ptr`.
      // used in `decodeFlat`
      function decodeValue (ptr) -> dataLen, valueOffset, isData {
        let firstByte := byte(0, calldataload(ptr))

        // SINGLE BYTE
        // 0x00 - 0x7f
        if lt(firstByte, 0x80) {
          dataLen := 1
          valueOffset := ptr
          isData := 1
          leave
        }

        // DATA ITEM
        // 0 - 55 bytes long
        // 0x80 - 0xb7
        if lt(firstByte, 0xb8) {
          dataLen := sub(firstByte, 0x80)
          valueOffset := add(ptr, 1)
          isData := 1
          leave
        }

        // LONG DATA ITEM
        // > 55 bytes
        // 0xb8 - 0xbf
        if lt(firstByte, 0xc0) {
          // the extended length is ignored
          dataLen := sub(firstByte, 0xb7)

          // load the extended length
          valueOffset := add(ptr, 1)
          let extendedLen := calldataload(valueOffset)
          let bits := sub(256, mul(dataLen, 8))
          valueOffset := add(ptr, dataLen)
          dataLen := shr(bits, extendedLen)
          leave
        }

        // everything else is unexpected
        revertWith('RLP')
      }

      // decodes all RLP encoded data and stores their DATA items
      // [length, calldata offset] in a continous memory region.
      // Expects that the RLP starts with a list that defines the length
      // of the whole RLP region.
      function decodeFlat (_ptr) -> ptr, memStart, nItems, hash {
        ptr := _ptr

        // load free memory ptr
        // doesn't update the ptr and leaves the memory region dirty
        memStart := mload(64)

        let payloadLen, startOffset := decodeListLength(ptr)
        // reuse memStart region and hash
        calldatacopy(memStart, ptr, payloadLen)
        hash := keccak256(memStart, payloadLen)

        let memPtr := memStart
        let ptrStop := add(ptr, payloadLen)
        ptr := startOffset

        // decode until the end of the list
        for {} lt(ptr, ptrStop) {} {
          let len, valuePtr, isData := decodeValue(ptr)
          ptr := add(len, valuePtr)

          if isData {
            // store the length of the data and the calldata offset
            let tmp := or(shl(128, len), valuePtr)
            mstore(memPtr, tmp)
            memPtr := add(memPtr, 32)
          }
        }

        nItems := div( sub(memPtr, memStart), 32 )
      }

      // expecting 16 individual items from the block header
      let calldataPtr, memStart, nItems, hash := decodeFlat(blockHeader.offset)

      // boundary check
      if iszero( eq(calldataPtr, add(blockHeader.offset, blockHeader.length)) ) {
        revertWith('BOUNDS')
      }
      if iszero( eq(hash, blockHash) ) {
        revertWith('HASH')
      }
      if iszero( eq(nItems, 16) ) {
        revertWith('ITEMS')
      }

      // at position 11 should be the timestamp
      let value, len := loadValue(add(memStart, mul(32, 11)))
      sstore(originTimestamp.slot, value)

      // at position 3 should be the stateRoot
      value, len := loadValue(add(memStart, mul(32, 3)))
      sstore(originStateRoot.slot, value)
    }
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
