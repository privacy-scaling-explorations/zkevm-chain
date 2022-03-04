contract L1BridgeEvents {
  event BlockSubmitted();
  event BlockFinalized(bytes32 blockHash);
  event L1MessageSent(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data);
}
