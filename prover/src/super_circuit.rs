use crate::circuit_witness::CircuitWitness;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::pi_circuit::gen_rand_rpi;
use zkevm_circuits::pi_circuit::PiCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::Curve;
use zkevm_circuits::tx_circuit::Group;
use zkevm_circuits::tx_circuit::Secp256k1Affine;
use zkevm_circuits::tx_circuit::TxCircuit;

/// Returns a instance of the `SuperCircuit`.
pub fn gen_circuit<
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
    RNG: Rng,
>(
    witness: &CircuitWitness,
    mut rng: RNG,
) -> Result<SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_RWS>, String> {
    let (block, keccak_inputs) = witness.evm_witness();
    let public_data = witness.public_data();
    let rand_rpi = gen_rand_rpi::<Fr, MAX_TXS, MAX_CALLDATA>(&public_data, block.randomness);
    let pi_circuit = PiCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        randomness: block.randomness,
        rand_rpi,
        public_data,
    };

    let chain_id = block.context.chain_id;
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
    let tx_circuit = TxCircuit::new(aux_generator, chain_id.as_u64(), witness.txs());
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_RWS> {
        block: Some(block),
        fixed_table_tags: FixedTableTag::iter().collect(),
        tx_circuit,
        keccak_inputs,
        bytecode_size: witness.circuit_config.max_bytecode,
        pi_circuit,
        circuits_params: witness.block.circuits_params.clone(),
    };

    Ok(circuit)
}
