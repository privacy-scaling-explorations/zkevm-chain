use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

pub type ProverParams = ParamsKZG<Bn256>;
pub type ProverCommitmentScheme = KZGCommitmentScheme<Bn256>;

pub mod aggregation_circuit;
pub mod circuit_autogen;
pub mod compute_proof;
pub mod server;
pub mod shared_state;
pub mod structs;
