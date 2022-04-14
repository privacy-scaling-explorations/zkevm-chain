import './PolynomialEval.sol';

// inspired by Espresso Systems (espressosys.com)
contract InstanceVerifier {
  function _verifyInstance(uint256 zeta, bytes calldata publicInputs) internal returns (uint256, uint256, uint256){
    require(publicInputs.length % 32 == 0, 'odd inputs');
    // TODO: prepare, verify inputs correctly and inline operations

    uint256[] memory publicInput = new uint256[](publicInputs.length / 32);
    assembly {
      calldatacopy(add(publicInput, 32), publicInputs.offset, publicInputs.length)
    }

    // fixed domain size k = 19
    PolynomialEval.EvalDomain memory domain = PolynomialEval.newEvalDomain(524288);
    // pre-compute evaluation data
    PolynomialEval.EvalData memory evalData = PolynomialEval.evalDataGen(domain, zeta, publicInput);

    // TODO: PCS

    return (
      evalData.vanishEval,
      evalData.lagrangeOne,
      evalData.piEval
    );
  }
}
