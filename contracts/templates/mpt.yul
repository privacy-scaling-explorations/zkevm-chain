// traverses the tree from the root to the node before the leaf.
// Note: `_depth` is untrusted.
function walkTree (key, _ptr) -> ptr, rootHash, expectedHash, path, leafMem {
  ptr := _ptr

  // the number of distinct proofs
  let nNodes  := byte(0, calldataload(ptr))
  ptr := add(ptr, 1)

  // keeps track of ascend/descend - however you may look at a tree
  let depth

  for { let i := 0 } lt(i, nNodes) { i := add(i, 1) } {
    let memStart, nItems, hash
    ptr, memStart, nItems, hash := decodeFlat(ptr)

    // first item is considered the root node.
    // Otherwise verifies that the hash of the current node
    // is the same as the previous choosen one.
    switch i
    case 0 {
      rootHash := hash
    } default {
      cmp(hash, expectedHash, 'THASH')
    }

    switch nItems
    case 2 {
      // extension node
      let value, len

      // load the second item.
      // this is the hash of the next node (account proof only)
      value, len := loadValueLen(memStart, 1)
      expectedHash := value

      switch eq(i, sub(nNodes, 1))
      case 0 {
        // get the byte length of the first item
        // Note: the value itself is not validated
        // and it is instead assumed that any invalid
        // value is invalidated by comparing the root hash.
        let prefixLen := shr(128, mload(memStart))
        depth := add(depth, prefixLen)
      }
      default {
        leafMem := memStart
      }
    }
    case 17 {
      let bits := sub(252, mul(depth, 4))
      let nibble := and(shr(bits, key), 0xf)

      // load the value at pos `nibble`
      let value, len := loadValueLen(memStart, nibble)

      expectedHash := value
      depth := add(depth, 1)
    }
    default {
      // everything else is unexpected
      revertWith('NODE')
    }
  }

  // lastly, derive the path of the choosen one (TM)
  path := derivePath(key, depth)
}

// Note: this doesn't work if there are no intermediate nodes before the leaf.
// This is not possible in practice because of the fact that there must be at least
// 2 accounts in the tree to make a transaction to a existing contract possible.
// Thus, 2 leaves.
function validateAccountProof (_ptr, accountAddress) -> ptr, rootHash, accountStorageHash {
  ptr := _ptr

  let encodedPath
  let path
  let hash
  let vlen
  let prevHash
  let leafMem
  let key := keccak_20(accountAddress)
  // `rootHash` is a return value and must be checked by the caller
  ptr, rootHash, prevHash, path, leafMem := walkTree(key, ptr)

  // 2 items
  // - encoded path
  // - account leaf RLP (4 items)
  require(leafMem, "ACLEAF")

  encodedPath := loadValue(leafMem, 0)
  // the calculated path must match the encoded path in the leaf
  cmp(path, encodedPath, 'ACROOT')

  // Load the position, length of the second element (RLP encoded)
  let leafPtr, leafLen := loadPair(leafMem, 1)
  let nItems
  leafPtr , leafMem, nItems, hash := decodeFlat(leafPtr)

  // the account leaf should contain 4 values,
  // we want:
  // - storageHash @ 2
  require(eq(nItems, 4), "ACLEAFN")
  accountStorageHash := loadValue(leafMem, 2)
}

// Supports inclusion & non-inclusion proof.
function validateStorageProof (_ptr, _storageKey) -> ptr, rootHash, storageKeyValue {
  ptr := _ptr

  let encodedPath
  let path
  let hash
  let vlen
  let leafMem
  let key := keccak_32(_storageKey)
  ptr, rootHash, hash, path, leafMem := walkTree(key, ptr)

  switch leafMem
  case 0 {
    // assuming empty / zero storage value
  }
  default {
    // leaf should contain 2 values
    // - encoded path @ 0
    // - storageValue @ 1
    encodedPath := loadValue(leafMem, 0)
    storageKeyValue, vlen := loadValueLen(leafMem, 1)
    // Assumes that `walktTree` follows `key`
    let isSamePath := eq(path, encodedPath)
    switch isSamePath
    case 0 {
      // The proof ends with a different item.
      storageKeyValue := 0
    }
    default {
      // The calculated path matches the encoded path in the leaf.
      // Storage value is RLP encoded.
      storageKeyValue := decodeItem(storageKeyValue, vlen)
    }
  }
}
