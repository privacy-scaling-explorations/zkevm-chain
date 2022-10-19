use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

pub type ProverParams = ParamsKZG<Bn256>;
pub type ProverCommitmentScheme = KZGCommitmentScheme<Bn256>;
pub type ProverKey = ProvingKey<G1Affine>;

pub mod aggregation_circuit;
pub mod circuit_autogen;
pub mod circuit_witness;
pub mod dummy_circuit;
pub mod public_input_circuit;
pub mod server;
pub mod shared_state;
pub mod super_circuit;
pub mod utils;
