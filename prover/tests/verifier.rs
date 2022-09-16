#![cfg(feature = "autogen")]

use eth_types::Bytes;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use itertools::Itertools;
use plonk_verifier::loader::evm::EvmLoader;
use plonk_verifier::loader::native::NativeLoader;
use plonk_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    util::transcript::TranscriptRead,
    verifier::PlonkVerifier,
};
use prover::aggregation_circuit::AggregationCircuit;
use prover::aggregation_circuit::Plonk;
use prover::aggregation_circuit::PoseidonTranscript;
use prover::aggregation_circuit::Snark;
use prover::compute_proof::gen_static_circuit;
use prover::compute_proof::gen_static_key;
use prover::compute_proof::gen_static_vk;
use prover::ProverCommitmentScheme;
use prover::ProverParams;
use rand::rngs::OsRng;
use std::fs;
use std::io::Cursor;
use std::io::Write;
use std::rc::Rc;
use zkevm_circuits::tx_circuit::POW_RAND_SIZE;

fn write_bytes(name: &str, vec: Vec<u8>) {
    let dir = "./../build/plonk-verifier";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/{}", dir, name);
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(format!("{}", Bytes::from(vec)).as_bytes())
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn load_params(k: usize) -> ProverParams {
    let params_path = format!("/testnet/{}.bin", k);
    let params_fs = fs::File::open(params_path).expect("couldn't open params");
    let params: ProverParams = ProverParams::read::<_>(&mut std::io::BufReader::new(params_fs))
        .expect("Failed to read params");

    params
}

fn gen_num_instance(params: &ProverParams) -> Vec<usize> {
    let mut num_instance = vec![params.n() as usize - 64; POW_RAND_SIZE];
    // SignVerifyChip -> ECDSAChip -> MainGate instance column
    num_instance.push(0);

    num_instance
}

fn gen_srs(k: u32) -> ProverParams {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_vk<C: Circuit<Fr>>(params: &ProverParams, circuit: &C) -> VerifyingKey<G1Affine> {
    keygen_vk(params, circuit).unwrap()
}

fn gen_evm_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let protocol = compile(
        vk,
        Config {
            // TODO: disable once supported
            zk: true,
            query_instance: false,
            num_instance: num_instance.clone(),
            num_proof: 1,
            accumulator_indices: None,
        },
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = num_instance
        .into_iter()
        .map(|len| transcript.read_n_scalars(len).unwrap())
        .collect_vec();
    let proof = Plonk::read_proof(&protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(
        &params.get_g()[0],
        &(params.g2(), params.s_g2()),
        &protocol,
        &instances,
        &proof,
    )
    .unwrap();

    loader.runtime_code()
}

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ProverParams,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<ProverCommitmentScheme, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    proof
}

fn gen_aggregation_evm_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
) -> Vec<u8> {
    let protocol = compile(
        vk,
        Config {
            zk: true,
            query_instance: false,
            num_instance: num_instance.clone(),
            num_proof: 1,
            accumulator_indices: Some(accumulator_indices),
        },
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = num_instance
        .into_iter()
        .map(|len| transcript.read_n_scalars(len).unwrap())
        .collect_vec();
    let proof = Plonk::read_proof(&protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(
        &params.get_g()[0],
        &(params.g2(), params.s_g2()),
        &protocol,
        &instances,
        &proof,
    )
    .unwrap();

    loader.runtime_code()
}

#[test]
fn autogen_verifier() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    prover::match_circuit_params!(
        50_000,
        {
            let params = load_params(MIN_K);
            let vk = gen_static_vk::<MAX_TXS, MAX_CALLDATA>(
                &params,
                BLOCK_GAS_LIMIT,
                MAX_BYTECODE,
                STATE_CIRCUIT_PAD_TO,
            )
            .expect("gen_static_vk");
            let num_instance = gen_num_instance(&params);

            let runtime_code = gen_evm_verifier(&params, &vk, num_instance);
            let path = format!("k{}", params.k());
            write_bytes(&path, runtime_code);
        },
        {
            panic!("no circuit parameters found");
        }
    );
}

#[test]
fn autogen_aggregation_verifier() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    prover::match_circuit_params!(
        50_000,
        {
            let snark = {
                let params = load_params(MIN_K);
                let pk = gen_static_key::<MAX_TXS, MAX_CALLDATA>(
                    &params,
                    BLOCK_GAS_LIMIT,
                    MAX_BYTECODE,
                    STATE_CIRCUIT_PAD_TO,
                )
                .expect("gen_static_pk");

                let circuit = gen_static_circuit::<MAX_TXS, MAX_CALLDATA>(
                    BLOCK_GAS_LIMIT,
                    MAX_BYTECODE,
                    STATE_CIRCUIT_PAD_TO,
                )
                .expect("gen_static_circuit");

                let mut instances: Vec<Vec<Fr>> = (1..POW_RAND_SIZE + 1)
                    .map(|exp| {
                        vec![
                            circuit.block.randomness.pow(&[exp as u64, 0, 0, 0]);
                            params.n() as usize - 64
                        ]
                    })
                    .collect();
                // SignVerifyChip -> ECDSAChip -> MainGate instance column
                instances.push(vec![]);

                let proof = gen_proof::<
                    _,
                    _,
                    PoseidonTranscript<NativeLoader, _, _>,
                    PoseidonTranscript<NativeLoader, _, _>,
                >(&params, &pk, circuit, instances.clone());

                let protocol = compile(
                    pk.get_vk(),
                    Config {
                        zk: true,
                        query_instance: false,
                        num_instance: gen_num_instance(&params),
                        num_proof: 1,
                        accumulator_indices: None,
                    },
                );

                Snark::new(protocol, instances, proof)
            };

            let params = gen_srs(21);
            let agg_circuit = AggregationCircuit::new(&params, [snark]);
            let vk = gen_vk(&params, &agg_circuit);
            let runtime_code = gen_aggregation_evm_verifier(
                &params,
                &vk,
                AggregationCircuit::num_instance(),
                AggregationCircuit::accumulator_indices(),
            );
            let path = format!("aggregator-k{}", params.k());
            write_bytes(&path, runtime_code);
        },
        {
            panic!("no circuit parameters found");
        }
    );
}
