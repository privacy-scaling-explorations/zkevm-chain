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

function require (cond, msg) {
  switch cond
  case 0 {
    revertWith(msg)
  }
}

// reverts with `msg` if `a != b`.
function cmp (a, b, msg) {
  switch eq(a, b)
  case 0 {
    revertWith(msg)
  }
}
