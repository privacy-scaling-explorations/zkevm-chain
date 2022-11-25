// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract CommonBlockOperations {
  function _readBlockHeader (
    bytes calldata blockHeader
  ) internal pure returns (bytes32 blockHash, bytes32 stateRoot, uint256 _timestamp) {
    assembly {
      //@INCLUDE:utils.yul
      //@INCLUDE:rlp.yul

      // expecting 16 individual items from the block header
      let calldataPtr, memStart, nItems, hash := decodeFlat(blockHeader.offset)

      // boundary check
      if iszero( eq(calldataPtr, add(blockHeader.offset, blockHeader.length)) ) {
        revertWith('BOUNDS')
      }
      if iszero( eq(nItems, 16) ) {
        revertWith('ITEMS')
      }

      blockHash := hash

      // at position 3 should be the stateRoot
      stateRoot := loadValue(memStart, 3)

      // at position 11 should be the timestamp
      _timestamp := loadValue(memStart, 11)
    }
  }
}
