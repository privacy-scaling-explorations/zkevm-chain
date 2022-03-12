import './interfaces/ICrossDomainMessenger.sol';
import './L1ZkEvmBridge.sol';

contract L1Messenger is ICrossDomainMessenger, L1ZkEvmBridge {
  address internal constant DEFAULT_XDOMAIN_SENDER = 0x000000000000000000000000000000000000dEaD;

  address xDomainMsgSender;

  function xDomainMessageSender () external view returns (address) {
    require(
      xDomainMsgSender != DEFAULT_XDOMAIN_SENDER,
      'xDomainMessageSender is not set'
    );
    return xDomainMsgSender;
  }

  function sendMessage (
    address _target,
    bytes calldata _message,
    uint32 _gasLimit
  ) external {
    uint256 fee = 0;
    uint256 deadline = block.timestamp + 1 days;
    uint256 nonce;
    assembly {
      nonce := add(gas(), add(difficulty(), timestamp()))
    }
    bool success = sendMessage(_target, fee, deadline, nonce, _message);
    require(success, 'SM1');
    emit SentMessage(_target, msg.sender, _message, nonce, _gasLimit);
  }
}
