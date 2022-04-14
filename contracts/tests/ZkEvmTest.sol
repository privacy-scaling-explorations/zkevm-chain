// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import '../PatriciaValidator.sol';
import '../verifier/InstanceVerifier.sol';

contract ZkEvmTest is PatriciaValidator, InstanceVerifier {
  function testPatricia (
    address account,
    bytes32 storageKey,
    bytes calldata proofData
  ) external pure returns (bytes32 stateRoot, bytes32 storageValue) {
    return _validatePatriciaProof(account, storageKey, proofData);
  }

  function testPublicInput(uint256 zeta, bytes calldata witness) external returns (uint256, uint256, uint256) {
    (uint256 vanish, uint256 lagrange, uint256 pi) = InstanceVerifier._verifyInstance(zeta, witness);

    return (vanish, lagrange, pi);
  }
}
