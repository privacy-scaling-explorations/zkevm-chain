// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../generated/PatriciaValidator.sol';
import '../generated/PublicInput.sol';

contract ZkEvmTest is PatriciaValidator, PublicInput {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) external pure returns (bytes32 stateRoot, bytes32 storageValue) {
    return _validatePatriciaProof(account, storageKey, proofData);
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
