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

      let ptr := proofData.offset
      ptr, stateRoot, storageHash := validateAccountProof(ptr, account)

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
