// decodes RLP at `_ptr`.
// reverts if the number of DATA items doesn't match `nValues`.
// returns the RLP data items at pos `v0`, `v1`
// and the size of `v1out`
function hashCompareSelect (_ptr, nValues, v0, v1) -> ptr, hash, v0out, v1out, v1outlen {
  ptr := _ptr

  let memStart, nItems
  ptr, memStart, nItems, hash := decodeFlat(ptr)

  if iszero( eq(nItems, nValues) ) {
    revertWith('NITEMS')
  }

  v0out, v1outlen := loadValueLen(memStart, v0)
  v1out, v1outlen := loadValueLen(memStart, v1)
}

// traverses the tree from the root to the node before the leaf.
// Note: `_depth` is untrusted.
function walkTree (key, _ptr) -> ptr, rootHash, expectedHash, path {
  ptr := _ptr

  // the number of distinct proofs - 1
  // (the leaf is treated differently)
  let nNodes  := sub(byte(0, calldataload(ptr)), 1)
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
      // this is the hash of the next node.
      value, len := loadValueLen(memStart, 1)
      expectedHash := value

      // get the byte length of the first item
      // Note: the value itself is not validated
      // and it is instead assumed that any invalid
      // value is invalidated by comparing the root hash.
      let prefixLen := shr(128, mload(memStart))
      depth := add(depth, prefixLen)
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
