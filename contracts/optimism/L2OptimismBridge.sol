// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;

import '../interfaces/ICrossDomainMessenger.sol';
import '../ZkEvmMagicNumbers.sol';
import './OptimismWrapper.sol';

contract L2OptimisimBridge is ICrossDomainMessenger, ZkEvmMagicNumbers, OptimismWrapper {
  function sendMessage(
    address _target,
    bytes calldata _message,
    uint32 _gasLimit
  ) external {
    _wrapMessage(L2_DISPATCHER, L1_OPTIMISM_WRAPPER, _target, _message, _gasLimit);
  }

  function relay (address from, address to, bytes calldata data) external {
    _relay(L2_DELIVERER, L1_OPTIMISM_WRAPPER, from, to, data);
  }
}
