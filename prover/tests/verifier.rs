#![cfg(feature = "autogen")]

use eth_types::Address;
use eth_types::Bytes;
use eth_types::U256;
use halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsProver;
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
use prover::circuit_witness::CircuitWitness;
use prover::dummy_circuit;
use prover::public_input_circuit;
use prover::super_circuit;
use prover::utils::collect_instance;
use prover::utils::fixed_rng;
use prover::utils::gen_num_instance;
use prover::utils::gen_proof;
use prover::ProverParams;
use std::fs;
use std::io::Write;
use std::rc::Rc;
use zkevm_common::prover::*;

#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize)]
struct Verifier {
    label: String,
    config: CircuitConfig,
    instance: Vec<U256>,
    proof: Bytes,
    runtime_code: Bytes,
    address: Address,
}

impl Verifier {
    fn build(&mut self) -> &Self {
        let mut tmp = [0; 20];
        let bytes = self.label.as_bytes();
        let x = 20 - bytes.len();
        for (i, v) in bytes.iter().enumerate() {
            tmp[i + x] = *v;
        }
        self.address = Address::from(tmp);

        self
    }
}

fn write_bytes(name: &str, vec: &[u8]) {
    let dir = "./../build/plonk-verifier";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/{}", dir, name);
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(vec)
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn load_params(k: usize) -> ProverParams {
    let params_path = format!("/testnet/{}.bin", k);
    let params_fs = fs::File::open(params_path).expect("couldn't open params");
    let params: ProverParams = ProverParams::read::<_>(&mut std::io::BufReader::new(params_fs))
        .expect("Failed to read params");

    params
}

fn gen_aggregation_evm_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    instance: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let num_instance = gen_num_instance(&instance);
    let config = Config::kzg()
        .with_num_instance(num_instance)
        .with_accumulator_indices(AggregationCircuit::accumulator_indices());

    gen_verifier(params, vk, instance, config)
}

fn gen_evm_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    instance: Vec<Vec<Fr>>,
) -> Vec<u8> {
    let num_instance = gen_num_instance(&instance);
    let config = Config::kzg().with_num_instance(num_instance);

    gen_verifier(params, vk, instance, config)
}

fn gen_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    instance: Vec<Vec<Fr>>,
    config: Config,
) -> Vec<u8> {
    let num_instance = gen_num_instance(&instance);
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(params, vk, config);

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.runtime_code()
}

macro_rules! test_aggregation {
    ($LABEL:expr, $CIRCUIT:ident, $GAS:expr) => {{
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .try_init();

        prover::match_circuit_params!(
            $GAS,
            {
                let snark = {
                    let witness = CircuitWitness::dummy(CIRCUIT_CONFIG.block_gas_limit).unwrap();
                    let circuit = $CIRCUIT::gen_circuit::<
                        { CIRCUIT_CONFIG.max_txs },
                        { CIRCUIT_CONFIG.max_calldata },
                        _,
                    >(&CIRCUIT_CONFIG, &witness, fixed_rng())
                    .expect("gen_static_circuit");
                    let instance = circuit.instance();

                    let params = load_params(CIRCUIT_CONFIG.min_k);
                    let vk = keygen_vk(&params, &circuit).expect("vk");
                    let pk = keygen_pk(&params, vk, &circuit).expect("pk");

                    {
                        let mut data = Verifier::default();
                        data.label = format!("{}-{}", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                        data.config = CIRCUIT_CONFIG;
                        data.runtime_code =
                            gen_evm_verifier(&params, &pk.get_vk(), circuit.instance()).into();

                        let proof = gen_proof::<
                            _,
                            _,
                            EvmTranscript<G1Affine, _, _, _>,
                            EvmTranscript<G1Affine, _, _, _>,
                            _,
                        >(
                            &params,
                            &pk,
                            circuit.clone(),
                            circuit.instance(),
                            fixed_rng(),
                        );
                        data.instance = collect_instance(&circuit.instance());
                        data.proof = proof.into();

                        let data = data.build();
                        write_bytes(&data.label, &serde_json::to_vec(data).unwrap());
                    }

                    let proof = gen_proof::<
                        _,
                        _,
                        PoseidonTranscript<NativeLoader, _, _>,
                        PoseidonTranscript<NativeLoader, _, _>,
                        _,
                    >(
                        &params, &pk, circuit, instance.clone(), fixed_rng()
                    );

                    let protocol = compile(
                        &params,
                        pk.get_vk(),
                        Config::kzg().with_num_instance(gen_num_instance(&instance)),
                    );

                    Snark::new(protocol, instance, proof)
                };

                let agg_params = load_params(CIRCUIT_CONFIG.min_k_aggregation);
                let agg_circuit = AggregationCircuit::new(&agg_params, [snark], fixed_rng());
                let agg_vk = keygen_vk(&agg_params, &agg_circuit).expect("vk");

                let mut data = Verifier::default();
                data.label = format!("{}-{}-a", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                data.config = CIRCUIT_CONFIG;
                data.runtime_code =
                    gen_aggregation_evm_verifier(&agg_params, &agg_vk, agg_circuit.instance())
                        .into();

                let agg_pk = keygen_pk(&agg_params, agg_vk, &agg_circuit).expect("pk");
                let proof = gen_proof::<
                    _,
                    _,
                    EvmTranscript<G1Affine, _, _, _>,
                    EvmTranscript<G1Affine, _, _, _>,
                    _,
                >(
                    &agg_params,
                    &agg_pk,
                    agg_circuit.clone(),
                    agg_circuit.instance(),
                    fixed_rng(),
                );
                data.instance = collect_instance(&agg_circuit.instance());
                data.proof = proof.into();

                let data = data.build();
                write_bytes(&data.label, &serde_json::to_vec(data).unwrap());
            },
            {
                panic!("no circuit parameters found");
            }
        );
    }};
}

#[test]
fn autogen_aggregation_super() {
    test_aggregation!("super", super_circuit, 63_000);
    test_aggregation!("super", super_circuit, 150_000);
    test_aggregation!("super", super_circuit, 300_000);
}

#[test]
fn autogen_aggregation_pi() {
    test_aggregation!("pi", public_input_circuit, 63_000);
    test_aggregation!("pi", public_input_circuit, 150_000);
    test_aggregation!("pi", public_input_circuit, 300_000);
}

#[test]
fn autogen_aggregation_dummy() {
    test_aggregation!("dummy", dummy_circuit, 63_000);
    test_aggregation!("dummy", dummy_circuit, 150_000);
    test_aggregation!("dummy", dummy_circuit, 300_000);
}
