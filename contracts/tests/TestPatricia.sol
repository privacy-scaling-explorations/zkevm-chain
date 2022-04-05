// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import '../PatriciaValidator.sol';

contract TestPatricia is PatriciaValidator {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) external pure returns (bytes32 stateRoot, bytes32 storageValue) {
    return _validatePatriciaProof(account, storageKey, proofData);
  }
}
