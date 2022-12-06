use crate::G1Affine;
use crate::ProverCommitmentScheme;
use crate::ProverKey;
use crate::ProverParams;
use eth_types::U256;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::poly::kzg::multiopen::VerifierGWC;
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use rand::rngs::StdRng;
use rand::Rng;
use zkevm_circuits::tx_circuit::PrimeField;

use rand::SeedableRng;
use std::clone::Clone;
use std::io::Cursor;

/// Returns [<len>, ...] of `instance`
pub fn gen_num_instance(instance: &[Vec<Fr>]) -> Vec<usize> {
    instance.iter().map(|v| v.len()).collect()
}

/// Returns the finalized transcript.
/// Runs the MockProver on `create_proof` error and panics afterwards.
pub fn gen_proof<
    C: Circuit<Fr> + Clone,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
    RNG: Rng,
>(
    params: &ProverParams,
    pk: &ProverKey,
    circuit: C,
    instance: Vec<Vec<Fr>>,
    rng: RNG,
    mock_feedback: bool,
    verify: bool,
) -> Vec<u8> {
    let mut transcript = TW::init(Vec::new());
    let inputs: Vec<&[Fr]> = instance.iter().map(|v| v.as_slice()).collect();
    let res = create_proof::<ProverCommitmentScheme, ProverGWC<_>, _, _, TW, _>(
        params,
        pk,
        &[circuit.clone()],
        &[inputs.as_slice()],
        rng,
        &mut transcript,
    );
    // run the `MockProver` and return (hopefully) useful errors
    if let Err(proof_err) = res {
        if mock_feedback {
            let res = MockProver::run(params.k(), &circuit, instance)
                .expect("MockProver::run")
                .verify_par();
            panic!("gen_proof: {:#?}\nMockProver: {:#?}", proof_err, res);
        } else {
            panic!("gen_proof: {:#?}", proof_err);
        }
    }

    let proof = transcript.finalize();
    if verify {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        let res = verify_proof::<_, VerifierGWC<_>, _, TR, _>(
            params.verifier_params(),
            pk.get_vk(),
            AccumulatorStrategy::new(params.verifier_params()),
            &[inputs.as_slice()],
            &mut transcript,
        );

        if let Err(verify_err) = res {
            panic!("verify_proof: {:#?}", verify_err);
        }
    }

    proof
}

/// Fixed rng for testing purposes
pub fn fixed_rng() -> StdRng {
    StdRng::seed_from_u64(9)
}

/// Collect circuit instance as flat vector
pub fn collect_instance(instance: &[Vec<Fr>]) -> Vec<U256> {
    instance
        .iter()
        .flatten()
        .map(|v| U256::from_little_endian(v.to_repr().as_ref()))
        .collect()
}
