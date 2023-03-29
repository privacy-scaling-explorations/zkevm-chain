// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../generated/PatriciaAccountValidator.sol';
import '../generated/PatriciaStorageValidator.sol';
import '../generated/PublicInput.sol';

contract ZkEvmTest is PatriciaAccountValidator, PatriciaStorageValidator, PublicInput {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata accountProof,
    bytes calldata storageProof
  ) external pure returns (bytes32 _stateRoot, bytes32 _storageValue) {
    (bytes32 proofStateRoot, bytes32 proofStorageRoot) = _validatePatriciaAccountProof(
      account,
      accountProof
    );
    (bytes32 storageRoot, bytes32 storageValue) = _validatePatriciaStorageProof(
      storageKey,
      storageProof
    );
    require(storageRoot == proofStorageRoot, 'STROOT');

    return (proofStateRoot, storageValue);
  }

  function testPublicInputCommitment(
    uint256 MAX_TXS,
    uint256 MAX_CALLDATA,
    uint256 chainId,
    uint256 parentStateRoot,
    bytes calldata witness
  ) external pure returns (uint256[] memory) {
    uint256[] memory publicInput =
      _buildCommitment(MAX_TXS, MAX_CALLDATA, chainId, parentStateRoot, witness, true);

    return publicInput;
  }
}
