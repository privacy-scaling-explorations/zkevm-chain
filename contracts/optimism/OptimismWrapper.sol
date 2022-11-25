// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../interfaces/ICrossDomainMessenger.sol';
import '../interfaces/IZkEvmMessageDispatcher.sol';
import '../interfaces/IZkEvmMessageDelivererWithProof.sol';
import '../ZkEvmUtils.sol';

abstract contract OptimismWrapper is ICrossDomainMessenger, ZkEvmUtils {
  address internal constant DEFAULT_XDOMAIN_SENDER = 0x000000000000000000000000000000000000dEaD;

  address xDomainMsgSender;

  function xDomainMessageSender () external view returns (address) {
    require(
      xDomainMsgSender != DEFAULT_XDOMAIN_SENDER,
      'xDomainMessageSender is not set'
    );
    return xDomainMsgSender;
  }

  function _wrapMessage (
    address fromBridge,
    address toBridge,
    address _target,
    bytes calldata _message,
    uint32 _gasLimit
  ) internal {
    uint256 fee = 0;
    uint256 deadline = block.timestamp + 1 days;
    uint256 nonce;
    assembly {
      nonce := add(gas(), add(difficulty(), timestamp()))
    }

    bytes memory data = abi.encodeWithSignature('relay(address,address,bytes)', msg.sender, _target, _message);
    IZkEvmMessageDispatcher(fromBridge).dispatchMessage(toBridge, fee, deadline, nonce, data);

    emit SentMessage(_target, msg.sender, _message, nonce, _gasLimit);
  }

  function _relay (address bridge, address fromWrapper, address from, address to, bytes calldata data) internal {
    require(msg.sender == bridge, 'sender');
    require(IZkEvmMessageDelivererWithProof(bridge).messageOrigin() == fromWrapper, 'message origin');

    xDomainMsgSender = from;
    _callAccount(to, 0, data);
    xDomainMsgSender = address(0);
  }
}
