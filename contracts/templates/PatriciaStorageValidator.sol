// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract PatriciaStorageValidator {
  function _validatePatriciaStorageProof (
    bytes32 storageKey,
    bytes calldata proofData
  ) internal pure returns (bytes32 storageRoot, bytes32 storageValue) {
    assembly {
      //@INCLUDE:rlp.yul
      //@INCLUDE:mpt.yul
      //@INCLUDE:utils.yul

      let ptr := proofData.offset
      ptr, storageRoot, storageValue := validateStorageProof(ptr, storageKey)

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
