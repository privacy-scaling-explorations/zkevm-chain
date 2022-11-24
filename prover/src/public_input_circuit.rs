use crate::circuit_witness::CircuitWitness;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use zkevm_circuits::pi_circuit::gen_rand_rpi;
use zkevm_circuits::pi_circuit::PiCircuit;

/// Returns a instance of the `PiCircuit`.
pub fn gen_circuit<
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
    RNG: Rng,
>(
    witness: &CircuitWitness,
    mut _rng: RNG,
) -> Result<PiCircuit<Fr, MAX_TXS, MAX_CALLDATA>, String> {
    let public_data = witness.public_data();
    let rand_rpi = gen_rand_rpi::<Fr, MAX_TXS, MAX_CALLDATA>(&public_data);
    let randomness = Fr::zero();
    let circuit = PiCircuit::<Fr, MAX_TXS, MAX_CALLDATA>::new(randomness, rand_rpi, public_data);

    Ok(circuit)
}
