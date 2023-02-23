// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract PatriciaStorageValidator {
  function _validatePatriciaStorageProof (
    bytes32 storageHash,
    bytes32 storageKey,
    bytes calldata proofData
  ) internal pure returns (bytes32 storageValue) {
    assembly {
      //@INCLUDE:rlp.yul
      //@INCLUDE:mpt.yul
      //@INCLUDE:utils.yul

      // starting point
      let ptr := proofData.offset
      {
        // storage proof
        let rootHash
        let encodedPath
        let path
        let hash
        let vlen
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
