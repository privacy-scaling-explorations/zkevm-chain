// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../interfaces/ICrossDomainMessenger.sol';
import '../ZkEvmMagicNumbers.sol';
import './OptimismWrapper.sol';

contract L1OptimismBridge is ICrossDomainMessenger, ZkEvmMagicNumbers, OptimismWrapper {
  function sendMessage(
    address _target,
    bytes calldata _message,
    uint32 _gasLimit
  ) external {
    _wrapMessage(L1_BRIDGE, L2_OPTIMISM_WRAPPER, _target, _message, _gasLimit);
  }

  function relay (address from, address to, bytes calldata data) external {
    _relay(L1_BRIDGE, L2_OPTIMISM_WRAPPER, from, to, data);
  }
}
