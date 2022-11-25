// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

contract ZkEvmBridgeEvents {
  event BlockSubmitted();
  event BlockFinalized(bytes32 blockHash);

  event MessageDispatched(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data);
  event MessageDelivered(bytes32 id);
  event MessageDropped(bytes32 id);
}
