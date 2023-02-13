pub use halo2_proofs::halo2curves::bn256::Bn256;
pub use halo2_proofs::halo2curves::bn256::Fq;
pub use halo2_proofs::halo2curves::bn256::Fr;
pub use halo2_proofs::halo2curves::bn256::G1Affine;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

pub const VERSION: &str = env!("PROVER_VERSION");
pub const MOCK_RANDOMNESS: u64 = 0x100;

pub type ProverParams = ParamsKZG<Bn256>;
pub type ProverCommitmentScheme = KZGCommitmentScheme<Bn256>;
pub type ProverKey = ProvingKey<G1Affine>;

pub mod circuit_autogen;
pub mod circuit_witness;
pub mod circuits;
pub mod server;
pub mod shared_state;
pub mod utils;
