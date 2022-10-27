use crate::circuit_witness::CircuitWitness;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use rand::Rng;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::pi_circuit::PiCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::Curve;
use zkevm_circuits::tx_circuit::Group;
use zkevm_circuits::tx_circuit::Secp256k1Affine;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_common::prover::CircuitConfig;

/// Returns a instance of the `SuperCircuit`.
pub fn gen_circuit<const MAX_TXS: usize, const MAX_CALLDATA: usize, RNG: Rng>(
    config: &CircuitConfig,
    witness: &CircuitWitness,
    mut rng: RNG,
) -> Result<SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA>, String> {
    let (mut block, keccak_inputs) = witness.evm_witness(config.pad_to);
    block.randomness = Fr::random(&mut rng);

    let pi_circuit = PiCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        randomness: Fr::random(&mut rng),
        rand_rpi: Fr::random(&mut rng),
        public_data: witness.public_data(),
    };

    let chain_id = block.context.chain_id;
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
    let tx_circuit = TxCircuit::new(aux_generator, chain_id.as_u64(), witness.txs());
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        block,
        fixed_table_tags: FixedTableTag::iter().collect(),
        tx_circuit,
        keccak_inputs,
        bytecode_size: config.max_bytecode,
        pi_circuit,
    };

    Ok(circuit)
}
