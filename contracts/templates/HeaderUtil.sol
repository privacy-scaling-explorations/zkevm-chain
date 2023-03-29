// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract HeaderUtil {
  function _readHeaderParts (
    bytes calldata blockHeader
  ) internal pure returns (
    bytes32 parentHash,
    bytes32 blockHash,
    bytes32 stateRoot,
    uint256 blockNumber,
    uint256 blockGasUsed,
    uint256 blockTimestamp
  ) {
    assembly {
      //@INCLUDE:utils.yul
      //@INCLUDE:rlp.yul

      // expecting 16 individual items from the block header
      let calldataPtr, memStart, nItems, hash := decodeFlat(blockHeader.offset)
      require(eq(nItems, 15), "BLOCK_ITEMS")

      // boundary check
      let end := add(blockHeader.offset, blockHeader.length)
      require(
        or(
          lt(calldataPtr, end),
          eq(calldataPtr, end)
        ),
        "BOUNDS"
      )

      blockHash := hash
      parentHash := loadValue(memStart, 0)
      stateRoot := loadValue(memStart, 3)
      blockNumber := loadValue(memStart, 8)
      blockGasUsed := loadValue(memStart, 10)
      blockTimestamp := loadValue(memStart, 11)
    }
  }
}
