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

    (bool success,) = to.call{value: value}(data);
    require(success, 'PM1');

    require(relayer.balance >= expectedBalance, 'PM2');

    emit L1MessageSent(from, to, value, fee, deadline, nonce, data);
  }
}
