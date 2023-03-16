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

      let ptr := proofData.offset

      // account proof
      let storageHash
      ptr, stateRoot, storageHash := validateAccountProof(ptr, account)

      // storage proof
      let rootHash
      ptr, rootHash, storageValue := validateStorageProof(ptr, storageKey)
      // The root hash of the storage tree must match the value from the account leaf.
      cmp(rootHash, storageHash, 'STROOT')

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
