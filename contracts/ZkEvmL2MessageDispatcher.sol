// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './interfaces/IZkEvmMessageDispatcher.sol';
import './interfaces/IZkEvmMessageDelivererWithProof.sol';
import './ZkEvmMessageDispatcherBase.sol';
import './generated/PatriciaStorageValidator.sol';

contract ZkEvmL2MessageDispatcher is
  IZkEvmMessageDispatcher,
  ZkEvmMessageDispatcherBase,
  PatriciaStorageValidator
{
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
    bytes calldata data,
    bytes calldata proof
  ) override external {
    // acquire ETH from L2_DELIVERER
    uint256 amount = value + fee;
    if (amount != 0) {
      (bool success,) = L2_DELIVERER.call(abi.encodeWithSignature('requestETH(uint256)', amount));
      require(success, 'RQETH');
    }
    // validate proof
    {
      bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));
      (bytes32 rootHash, bytes32 storageValue) = _validatePatriciaStorageProof(
        _PENDING_MESSAGE_KEY(messageHash),
        proof
      );
      require(storageValue == 0, 'DMVAL');
      // verify rootHash
      require(rootHash != 0, 'STROOT');
      uint256 originTimestamp = IZkEvmMessageDelivererWithProof(L2_DELIVERER).getTimestampForStorageRoot(rootHash);
      require(originTimestamp > deadline, 'DMTS');
    }

    _dropMessage(from, to, value, fee, deadline, nonce, data);
  }

  receive () external payable {
    require(msg.sender == L2_DELIVERER, 'MSED');
  }
}
