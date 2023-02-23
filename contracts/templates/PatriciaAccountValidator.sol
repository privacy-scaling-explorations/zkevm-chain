// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract PatriciaAccountValidator {
  function _validatePatriciaAccountProof (
    address account,
    bytes calldata proofData
  ) internal pure returns (bytes32 stateRoot, bytes32 storageHash) {
    assembly {
      //@INCLUDE:rlp.yul
      //@INCLUDE:mpt.yul
      //@INCLUDE:utils.yul

      // starting point
      let ptr := proofData.offset

      {
        // account proof
        // Note: this doesn't work if there are no intermediate nodes before the leaf.
        // This is not possible in practice because of the fact that there must be at least
        // 2 accounts in the tree to make a transaction to a existing contract possible.
        // Thus, 2 leaves.
        let encodedPath
        let path
        let hash
        let vlen
        let prevHash
        let key := keccak_20(account)
        // `stateRoot` is a return value and must be checked by the caller
        ptr, stateRoot, prevHash, path := walkTree(key, ptr)

        let memStart, nItems
        ptr, memStart, nItems, hash := decodeFlat(ptr)

        // the hash of the leaf must match the previous hash from the node
        cmp(hash, prevHash, 'ACLEAFH')

        // 2 items
        // - encoded path
        // - account leaf RLP (4 items)
        require(eq(nItems, 2), "ACLEAF")

        encodedPath := loadValue(memStart, 0)
        // the calculated path must match the encoded path in the leaf
        cmp(path, encodedPath, 'ACROOT')

        // Load the position, length of the second element (RLP encoded)
        let leafPtr, leafLen := loadPair(memStart, 1)
        leafPtr , memStart, nItems, hash := decodeFlat(leafPtr)

        // the account leaf should contain 4 values,
        // we want:
        // - storageHash @ 2
        require(eq(nItems, 4), "ACLEAFN")
        storageHash := loadValue(memStart, 2)
      }

      // the one and only boundary check
      // in case an attacker crafted a malicous payload
      // and succeeds in the prior verification steps
      // then this should catch any bogus accesses
      if iszero( eq(ptr, add(proofData.offset, proofData.length)) ) {
        revertWith('BOUNDS')
      }
    }
  }
}
