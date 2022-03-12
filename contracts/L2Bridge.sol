import "./Utils.sol";
import "./L2BridgeEvents.sol";

contract L2Bridge is Utils, L2BridgeEvents {
  function processMessage (
    address from,
    address to,
    uint256 value,
    uint256 fee,
    uint256 deadline,
    uint256 nonce,
    bytes calldata data
  ) external {
    Utils._onlyEOA();

    address relayer;
    assembly {
      relayer := origin()
    }
    uint256 expectedBalance = relayer.balance + fee;

    xDomainMsgSender = from;
    assembly {
      let ptr := 128
      calldatacopy(ptr, data.offset, data.length)
      if iszero(call(gas(), to, value, ptr, data.length, 0, 0)) {
        returndatacopy(0, 0, returndatasize())
        revert(0, returndatasize())
      }
    }
    xDomainMsgSender = address(0);

    require(relayer.balance >= expectedBalance, 'PM1');

    emit L1MessageSent(from, to, value, fee, deadline, nonce, data);
  }

  // should be moved to it's own contract @ 0x4200000000000000000000000000000000000007
  address xDomainMsgSender;

  function xDomainMessageSender () external view returns (address) {
    return xDomainMsgSender;
  }
}
