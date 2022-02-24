import "./L1BridgeEvents.sol";

contract L1Bridge is L1BridgeEvents {
  bytes32 public safeBlockHash;
  bytes32 public finalizedBlockHash;
  mapping (bytes32 => uint256) public pendingMessages;

  function submitBlock (bytes calldata _data) external {
    _onlyEOA();

    safeBlockHash = keccak256(_data);

    emit BlockSubmitted();
  }

  function finalizeBlock (bytes32 blockHash, bytes calldata _witness, bytes calldata _proof) external {
    finalizedBlockHash = blockHash;

    emit BlockFinalized(blockHash);
  }

  function sendMessage (address to, uint256 fee, bytes calldata _data) external payable {
    bytes32 messageHash = keccak256(abi.encode(msg.sender, to, msg.value, fee, _data));
    pendingMessages[messageHash] = block.timestamp;

    emit L1MessageSent(msg.sender, to, msg.value, fee, _data);
  }

  /// @dev Revert if caller is not tx sender.
  /// Thus, we make sure that only regular accounts can submit blocks.
  function _onlyEOA () internal view {
    assembly {
      if iszero(eq(origin(), caller())) {
        revert(0, 0)
      }
    }
  }

}
