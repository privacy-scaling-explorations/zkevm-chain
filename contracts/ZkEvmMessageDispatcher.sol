// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './interfaces/IZkEvmMessageDispatcher.sol';
import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';

contract ZkEvmMessageDispatcher is IZkEvmMessageDispatcher, ZkEvmUtils, ZkEvmMagicNumbers, ZkEvmBridgeEvents {
  mapping (bytes32 => uint256) pendingMessages;

  /// @inheritdoc IZkEvmMessageDispatcher
  function dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) virtual external payable returns (bytes32 messageHash) {
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
  ) virtual external {
    _dropMessage(from, to, value, fee, deadline, nonce, data);
  }

  function _dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) internal returns (bytes32 messageHash) {
    require(deadline > block.timestamp + MIN_MESSAGE_LOCK_SECONDS, 'DMD');

    // assuming underflow check
    uint256 value = msg.value - fee;

    messageHash = keccak256(abi.encode(msg.sender, to, value, fee, deadline, nonce, data));

    require(pendingMessages[messageHash] == 0, 'DMH');
    pendingMessages[messageHash] = uint256(uint160(msg.sender));

    emit MessageDispatched(msg.sender, to, value, fee, deadline, nonce, data);
  }

  function _dropMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) internal {
    require(block.timestamp > deadline, 'DMD');

    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));

    require(pendingMessages[messageHash] != 0, 'DMH');
    pendingMessages[messageHash] = 0;

    uint256 amount = value + fee;
    if (amount != 0) {
      _transferETH(from, amount);
    }

    emit MessageDropped(messageHash);
  }
}
