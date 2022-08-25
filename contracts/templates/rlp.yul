// special function for decoding the storage value
// because of the prefix truncation if value > 31 bytes
// see `loadValue`
function decodeItem (word, len) -> ret {
  // default
  ret := word

  // RLP single byte
  if lt(word, 0x80) {
    leave
  }

  // truncated
  if gt(len, 32) {
    leave
  }

  // value is >= 0x80 and <= 32 bytes.
  // `len` should be at least 2 (prefix byte + value)
  // otherwise the RLP is malformed.
  let bits := mul(len, 8)
  // sub 8 bits - the prefix
  bits := sub(bits, 8)
  let mask := shl(bits, 0xff)
  // invert the mask
  mask := not(mask)
  // should hold the value - prefix byte
  ret := and(ret, mask)
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
    if gt(lenOf, 4) {
      invalid()
    }

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
    let lenOf := sub(firstByte, 0xb7)
    if gt(lenOf, 4) {
      invalid()
    }

    // load the extended length
    valueOffset := add(ptr, 1)
    let extendedLen := calldataload(valueOffset)
    let bits := sub(256, mul(lenOf, 8))
    extendedLen := shr(bits, extendedLen)

    dataLen := extendedLen
    valueOffset := add(valueOffset, lenOf)
    isData := 1
    leave
  }

  // SHORT LIST
  // 0 - 55 bytes
  // 0xc0 - 0xf7
  if lt(firstByte, 0xf8) {
    // intentionally ignored
    // dataLen := sub(firstByte, 0xbf)
    valueOffset := add(ptr, 1)
    leave
  }

  // LONG LIST
  // 0xf8 - 0xff
  // > 55 bytes
  {
    // the extended length is ignored
    dataLen := sub(firstByte, 0xf7)
    valueOffset := add(ptr, 1)
    leave
  }
}

// decodes all RLP encoded data and stores their DATA items
// [length - 128 bits | calldata offset - 128 bits] in a continous memory region.
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

  if iszero(eq(ptr, ptrStop)) {
    invalid()
  }

  nItems := div( sub(memPtr, memStart), 32 )
}

// hashes 32 bytes of `v`
function keccak_32 (v) -> r {
  mstore(0, v)
  r := keccak256(0, 32)
}

// hashes the last 20 bytes of `v`
function keccak_20 (v) -> r {
  mstore(0, v)
  r := keccak256(12, 20)
}

// prefix gets truncated to 256 bits
// `depth` is untrusted and can lead to bogus
// shifts/masks. In that case, the remaining verification
// steps must fail or lead to an invalid stateRoot hash
// if the proof data is 'spoofed but valid'
function derivePath (key, depth) -> path {
  path := key

  let bits := mul(depth, 4)
  {
    let mask := not(0)
    mask := shr(bits, mask)
    path := and(path, mask)
  }

  // even prefix
  let prefix := 0x20
  if mod(depth, 2) {
    // odd
    prefix := 0x3
  }

  // the prefix may be shifted outside bounds
  // this is intended, see `loadValue`
  bits := sub(256, bits)
  prefix := shl(bits, prefix)
  path := or(prefix, path)
}

// loads and aligns a value from calldata
// given the `len|offset` stored at `memPtr`
function loadValue (memPtr, idx) -> value {
  let tmp := mload(add(memPtr, mul(32, idx)))
  // assuming 0xffffff is sufficient for storing calldata offset
  let offset := and(tmp, 0xffffff)
  let len := shr(128, tmp)

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

// loads and aligns a value from calldata
// given the `len|offset` stored at `memPtr`
// Same as `loadValue` except it returns also the size
// of the value.
function loadValueLen (memPtr, idx) -> value, len {
  let tmp := mload(add(memPtr, mul(32, idx)))
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

function loadPair (memPtr, idx) -> offset, len {
  let tmp := mload(add(memPtr, mul(32, idx)))
  // assuming 0xffffff is sufficient for storing calldata offset
  offset := and(tmp, 0xffffff)
  len := shr(128, tmp)
}
