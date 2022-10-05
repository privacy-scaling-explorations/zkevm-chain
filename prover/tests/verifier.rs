#![cfg(feature = "autogen")]

use eth_types::Bytes;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::EncodedChallenge;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::transcript::TranscriptWriterBuffer;
use itertools::Itertools;
use plonk_verifier::loader::evm::EvmLoader;
use plonk_verifier::loader::native::NativeLoader;
use plonk_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::PlonkVerifier,
};
use prover::aggregation_circuit::AggregationCircuit;
use prover::aggregation_circuit::Plonk;
use prover::aggregation_circuit::PoseidonTranscript;
use prover::aggregation_circuit::Snark;
use prover::compute_proof::gen_instances;
use prover::compute_proof::gen_static_circuit;
use prover::compute_proof::gen_static_key;
use prover::ProverCommitmentScheme;
use prover::ProverParams;
use rand::rngs::OsRng;
use std::fs;
use std::io::Cursor;
use std::io::Write;
use std::rc::Rc;

fn write_bytes(name: &str, vec: &[u8]) {
    let dir = "./../build/plonk-verifier";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/{}", dir, name);
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(format!("{}", Bytes::from(Vec::from(vec))).as_bytes())
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn load_params(k: usize) -> ProverParams {
    let params_path = format!("/testnet/{}.bin", k);
    let params_fs = fs::File::open(params_path).expect("couldn't open params");
    let params: ProverParams = ProverParams::read::<_>(&mut std::io::BufReader::new(params_fs))
        .expect("Failed to read params");

    params
}

fn gen_num_instance(instances: &[Vec<Fr>]) -> Vec<usize> {
    instances.iter().map(|e| e.len()).collect()
}

fn gen_vk<C: Circuit<Fr>>(params: &ProverParams, circuit: &C) -> VerifyingKey<G1Affine> {
    keygen_vk(params, circuit).unwrap()
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
    MockProver::run(params.k(), &circuit, instances.clone())
        .expect("MockProver::run")
        .assert_satisfied();

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

fn gen_aggregation_evm_verifier(params: &ProverParams, vk: &VerifyingKey<G1Affine>) -> Vec<u8> {
    let num_instance = AggregationCircuit::num_instance();
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(AggregationCircuit::accumulator_indices()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.runtime_code()
}

#[test]
fn autogen_aggregation_verifier() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    let agg_params = load_params(21);
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

                let mut circuit = gen_static_circuit::<MAX_TXS, MAX_CALLDATA>(
                    BLOCK_GAS_LIMIT,
                    MAX_BYTECODE,
                    STATE_CIRCUIT_PAD_TO,
                )
                .expect("gen_static_circuit");
                circuit.block.randomness = Fr::from(1);

                let instances = gen_instances().unwrap();
                let proof = gen_proof::<
                    _,
                    _,
                    PoseidonTranscript<NativeLoader, _, _>,
                    PoseidonTranscript<NativeLoader, _, _>,
                >(&params, &pk, circuit, instances.clone());

                let path = format!("proof-k{}", params.k());
                write_bytes(&path, &proof);

                let protocol = compile(
                    &params,
                    pk.get_vk(),
                    Config::kzg().with_num_instance(gen_num_instance(&instances)),
                );

                Snark::new(protocol, instances, proof)
            };

            let agg_circuit = AggregationCircuit::new(&agg_params, [snark]);
            let vk = gen_vk(&agg_params, &agg_circuit);
            let runtime_code = gen_aggregation_evm_verifier(&agg_params, &vk);
            let path = format!("aggregator-k{}", agg_params.k());
            write_bytes(&path, &runtime_code);
        },
        {
            panic!("no circuit parameters found");
        }
    );
}
