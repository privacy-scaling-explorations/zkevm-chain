// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../generated/PatriciaValidator.sol';
import '../generated/InstanceVerifier.sol';
import '../generated/PublicInput.sol';

contract ZkEvmTest is PatriciaValidator, InstanceVerifier, PublicInput {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) external pure returns (bytes32 stateRoot, bytes32 storageValue) {
    return _validatePatriciaProof(account, storageKey, proofData);
  }

  function testPublicInput(
    uint256 MAX_TXS,
    uint256 MAX_CALLDATA,
    uint256 chainId,
    uint256 parentStateRoot,
    bytes calldata witness
  ) external pure returns (uint256[] memory) {
    (uint256[] memory publicInput,) =
      _buildTable(MAX_TXS, MAX_CALLDATA, chainId, parentStateRoot, witness, false);

    // Use of assembly here because it otherwise does
    // a whole copy of `publicInput`.
    assembly {
      let ptr := sub(publicInput, 32)
      mstore(ptr, 0x20)
      let len := add(mul(mload(publicInput), 32), 64)
      return(ptr, len)
    }
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
