// SPDX-License-Identifier: UNLICENSED
pragma solidity <0.9.0;

import './ZkEvmMessageDelivererBase.sol';
import './interfaces/IZkEvmMessageDelivererWithoutProof.sol';

contract ZkEvmL2MessageDeliverer is
  ZkEvmMessageDelivererBase,
  IZkEvmMessageDelivererWithoutProof
{
  /// @inheritdoc IZkEvmMessageDelivererWithoutProof
  function deliverMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external {
    _onlyEOA();
    // avoid calling the 'requestETH' or any other 'administrative' functions from L2_DELIVERER
    require(to != L2_DISPATCHER, 'TNED');

    _deliverMessage(from, to, value, fee, deadline, nonce, data);
  }

  function requestETH (uint256 amount) external {
    require(msg.sender == L2_DISPATCHER, 'MSEDS');

    _transferETH(msg.sender, amount);
  }

  receive () external payable {
    require(msg.sender == L2_DISPATCHER, 'MSEDS');
  }
}
