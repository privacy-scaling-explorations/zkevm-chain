use crate::circuit_witness::CircuitWitness;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use zkevm_circuits::pi_circuit::PiCircuit;
use zkevm_common::prover::CircuitConfig;

/// Returns a instance of the `PiCircuit`.
pub fn gen_circuit<const MAX_TXS: usize, const MAX_CALLDATA: usize, RNG: Rng>(
    _config: &CircuitConfig,
    witness: &CircuitWitness,
    mut rng: RNG,
) -> Result<PiCircuit<Fr, MAX_TXS, MAX_CALLDATA>, String> {
    let public_data = witness.public_data();
    let randomness = Fr::random(&mut rng);
    let rand_rpi = Fr::random(&mut rng);
    let circuit = PiCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        randomness,
        rand_rpi,
        public_data,
    };

    Ok(circuit)
}
