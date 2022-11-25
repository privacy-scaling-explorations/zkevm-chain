// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './ZkEvmMessageDispatcher.sol';

contract ZkEvmL2MessageDispatcher is ZkEvmMessageDispatcher {
  /// @inheritdoc IZkEvmMessageDispatcher
  function dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) override external payable returns (bytes32 messageHash) {
    // send ETH to L2_DELIVERER
    if (msg.value != 0) {
      _transferETH(L2_DELIVERER, msg.value);
    }
    messageHash = _dispatchMessage(to, fee, deadline, nonce, data);
  }

  /// @inheritdoc IZkEvmMessageDispatcher
  function dropMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) override external {
    // acquire ETH from L2_DELIVERER
    uint256 amount = value + fee;
    if (amount != 0) {
      (bool success,) = L2_DELIVERER.call(abi.encodeWithSignature('requestETH(uint256)', amount));
      require(success, 'RQETH');
    }
    _dropMessage(from, to, value, fee, deadline, nonce, data);
  }

  receive () external payable {
    require(msg.sender == L2_DELIVERER, 'MSED');
  }
}
