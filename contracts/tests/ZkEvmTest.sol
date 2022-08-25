// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import '../PatriciaValidator.sol';
import '../generated/InstanceVerifier.sol';

contract ZkEvmTest is PatriciaValidator, InstanceVerifier {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) external pure returns (bytes32 stateRoot, bytes32 storageValue) {
    return _validatePatriciaProof(account, storageKey, proofData);
  }

  function testPublicInput(
    uint256 zeta,
    uint256 MAX_TXS,
    uint256 MAX_CALLDATA,
    uint256 chainId,
    uint256 parentStateRoot,
    bytes calldata witness
  ) external returns (uint256[] memory) {
    (uint256[] memory publicInput, uint256 blockHash) =
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
}
