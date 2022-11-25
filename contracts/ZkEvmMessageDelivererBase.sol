// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import './interfaces/IZkEvmMessageDelivererBase.sol';
import './ZkEvmUtils.sol';
import './ZkEvmMagicNumbers.sol';
import './ZkEvmBridgeEvents.sol';

contract ZkEvmMessageDelivererBase is
  IZkEvmMessageDelivererBase,
  ZkEvmUtils,
  ZkEvmMagicNumbers,
  ZkEvmBridgeEvents
{
  address _messageOrigin;

  /// @inheritdoc IZkEvmMessageDelivererBase
  function messageOrigin () external view returns (address) {
    return _messageOrigin;
  }

  /// @dev Common routine for `deliverMessage` or `deliverMessageWithProof`.
  function _deliverMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) internal {
    require(block.timestamp < deadline, 'DMD');

    bytes32 messageHash = keccak256(abi.encode(from, to, value, fee, deadline, nonce, data));

    if (fee != 0) {
      _transferETH(tx.origin, fee);
    }

    _messageOrigin = from;
    _callAccount(to, value, data);
    _messageOrigin = address(0);

    emit MessageDelivered(messageHash);
  }
}
