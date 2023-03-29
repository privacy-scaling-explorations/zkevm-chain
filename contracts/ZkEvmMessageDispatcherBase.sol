// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';
import './ZkEvmStorage.sol';

contract ZkEvmMessageDispatcherBase is ZkEvmUtils, ZkEvmMagicNumbers, ZkEvmBridgeEvents, ZkEvmStorage {
  function _dispatchMessage (
    address to,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) internal returns (bytes32 messageHash) {
    // require(deadline > block.timestamp + MIN_MESSAGE_LOCK_SECONDS, 'DMD');

    // assuming underflow check
    uint256 value = msg.value - fee;

    messageHash = keccak256(abi.encode(msg.sender, to, value, fee, deadline, nonce, data));

    bytes32 storageSlot = _PENDING_MESSAGE_KEY(messageHash);
    require(_sload(storageSlot) == 0, 'DMH');
    _sstore(storageSlot, bytes32(uint256(1)));

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

    bytes32 storageSlot = _PENDING_MESSAGE_KEY(messageHash);
    require(_sload(storageSlot) != 0, 'DMH');
    _sstore(storageSlot, 0);

    uint256 amount = value + fee;
    if (amount != 0) {
      _transferETH(from, amount);
    }

    emit MessageDropped(messageHash);
  }

  function _sload (bytes32 key) internal view returns (uint256 ret) {
    assembly {
      ret := sload(key)
    }
  }

  function _sstore (bytes32 key, bytes32 value) internal {
    assembly {
      sstore(key, value)
    }
  }
}
