// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract PatriciaValidator {
  /// @dev This function validates a proof from eth_getCode.
  /// Intended for non-zero storage slots only.
  /// @param account The address of the contract.
  /// @param storageKey The storage slot in question.
  /// @param proofData Should contain:
  /// <1 byte - len of accountProof items>
  /// < concat accountProof>
  /// < 1 byte - len of storageProof items>
  /// < concat storageProof >
  /// @return stateRoot The computed state root. Must be checked by the caller.
  /// @return storageValue The value of `storageKey`.
  function _validatePatriciaProof (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) internal pure returns (bytes32 stateRoot, bytes32 storageValue) {
    assembly {
      //@INCLUDE:rlp.yul
      //@INCLUDE:mpt.yul
      //@INCLUDE:utils.yul

      // shared variable names
      let storageHash
      let encodedPath
      let path
      let hash
      let vlen
      // starting point
      let ptr := proofData.offset

      {
        // account proof
        // Note: this doesn't work if there are no intermediate nodes before the leaf.
        // This is not possible in practice because of the fact that there must be at least
        // 2 accounts in the tree to make a transaction to a existing contract possible.
        // Thus, 2 leaves.
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


      {
        // storage proof
        let rootHash
        let key := keccak_32(storageKey)
        ptr, rootHash, hash, path := walkTree(key, ptr)

        // leaf should contain 2 values
        // - encoded path @ 0
        // - storageValue @ 1
        ptr, hash, encodedPath, storageValue, vlen := hashCompareSelect(ptr, 2, 0, 1)
        // the calculated path must match the encoded path in the leaf
        cmp(path, encodedPath, 'STLEAF')

        switch rootHash
        case 0 {
          // in the case that the leaf is the only element, then
          // the hash of the leaf must match the value from the account leaf
          cmp(hash, storageHash, 'STROOT')
        }
        default {
          // otherwise the root hash of the storage tree
          // must match the value from the account leaf
          cmp(rootHash, storageHash, 'STROOT')
        }

        // storageValue is a return value
        storageValue := decodeItem(storageValue, vlen)
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
