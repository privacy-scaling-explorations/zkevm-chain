import "./Utils.sol";
import "./L1Environment.sol";
import "./L1BridgeEvents.sol";

contract L1ZkEvmBridge is Utils, L1Environment, L1BridgeEvents {
  bytes32 public safeBlockHash;
  bytes32 public finalizedBlockHash;
  mapping (bytes32 => uint256) public pendingMessages;

  function submitBlock (bytes calldata _data) external {
    Utils._onlyEOA();

    safeBlockHash = keccak256(_data);

    emit BlockSubmitted();
  }

  function finalizeBlock (bytes32 blockHash, bytes calldata _witness, bytes calldata _proof) external {
    finalizedBlockHash = blockHash;

    emit BlockFinalized(blockHash);
  }

  function sendMessage (address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) public payable returns (bool) {
    require(deadline > block.timestamp + MIN_MESSAGE_LOCK_SECONDS, 'SM1');
    bytes32 messageHash = keccak256(abi.encode(msg.sender, to, msg.value, fee, deadline, nonce, _data));
    require(pendingMessages[messageHash] == 0, 'SM2');
    pendingMessages[messageHash] = uint256(uint160(msg.sender));

    emit L1MessageSent(msg.sender, to, msg.value, fee, deadline, nonce, _data);

    return true;
  }
}
