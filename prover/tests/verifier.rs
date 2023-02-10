#![cfg(feature = "autogen")]

use eth_types::Address;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsProver;
use prover::circuit_witness::CircuitWitness;
use prover::circuits::*;
use prover::utils::fixed_rng;
use prover::utils::gen_num_instance;
use prover::utils::gen_proof;
use prover::Bn256;
use prover::ProverParams;
use prover::{Fq, Fr, G1Affine};
use rand::rngs::OsRng;
use snark_verifier::cost::CostEstimation;
use snark_verifier::loader::evm::EvmLoader;
use snark_verifier::util::transcript::TranscriptWrite;
use snark_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::SnarkVerifier,
};
use std::env::var;
use std::fs;
use std::io::Write;
use std::rc::Rc;
use zkevm_circuits::root_circuit::KzgDk;
use zkevm_circuits::root_circuit::KzgSvk;
use zkevm_circuits::root_circuit::PlonkSuccinctVerifier;
use zkevm_circuits::root_circuit::PlonkVerifier;
use zkevm_circuits::root_circuit::PoseidonTranscript;
use zkevm_circuits::root_circuit::RootCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_common::prover::*;

#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize)]
struct Verifier {
    label: String,
    config: CircuitConfig,
    code: String,
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

    fn write_yul(&mut self) -> &Self {
        self.build();
        let file_name = format!("verifier-{}-{:?}.yul", self.label, self.address);
        // only keep the runtime section
        let yul_code = format!("object \"{}\" ", self.label)
            + self.code.split("object \"Runtime\"").last().unwrap();
        // strip of the dangling `}`
        let yul_code = &yul_code[0..yul_code.len() - 1];
        write_bytes(&file_name, yul_code.as_bytes());

        self
    }
}

fn write_bytes(name: &str, vec: &[u8]) {
    let dir = "./../contracts/generated/";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {dir}"));
    let path = format!("{dir}/{name}");
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(vec)
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn gen_verifier(
    params: &ProverParams,
    vk: &VerifyingKey<G1Affine>,
    config: Config,
    num_instance: Vec<usize>,
) -> String {
    let protocol = compile(params, vk, config);
    let svk = KzgSvk::<Bn256>::new(params.get_g()[0]);
    let dk = KzgDk::<Bn256>::new(svk, params.g2(), params.s_g2());

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::verify(&dk, &protocol, &instances, &proof).unwrap();

    loader.yul_code()
}

macro_rules! gen_match {
    ($LABEL:expr, $CIRCUIT:ident, $GAS:expr) => {{
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        prover::match_circuit_params!(
            $GAS,
            {
                let (protocol, instance, proof) = {
                    let witness = CircuitWitness::dummy(CIRCUIT_CONFIG).unwrap();
                    let circuit = $CIRCUIT::<
                        { CIRCUIT_CONFIG.max_txs },
                        { CIRCUIT_CONFIG.max_calldata },
                        { CIRCUIT_CONFIG.max_rws },
                        { CIRCUIT_CONFIG.max_copy_rows },
                        _,
                    >(&witness, fixed_rng())
                    .expect("gen_static_circuit");
                    let params = ProverParams::setup(CIRCUIT_CONFIG.min_k as u32, fixed_rng());
                    let vk = keygen_vk(&params, &circuit).expect("vk");
                    let instance = circuit.instance();

                    {
                        let mut data = Verifier::default();
                        data.label = format!("{}-{}", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                        data.config = CIRCUIT_CONFIG;
                        data.code = gen_verifier(
                            &params,
                            &vk,
                            Config::kzg().with_num_instance(gen_num_instance(&instance)),
                            gen_num_instance(&instance),
                        )
                        .into();
                        data.write_yul();

                        if var("ONLY_EVM").is_ok() {
                            log::info!("returning early");
                            return;
                        }
                    }

                    let protocol = compile(
                        &params,
                        &vk,
                        Config::kzg().with_num_instance(gen_num_instance(&instance)),
                    );

                    let proof = if var("FAST").is_ok() {
                        let mut transcript = PoseidonTranscript::<_, _>::new(Vec::new());

                        for _ in 0..protocol
                            .num_witness
                            .iter()
                            .chain(Some(&protocol.quotient.num_chunk()))
                            .sum::<usize>()
                        {
                            transcript.write_ec_point(G1Affine::random(OsRng)).unwrap();
                        }

                        for _ in 0..protocol.evaluations.len() {
                            transcript.write_scalar(Fr::random(OsRng)).unwrap();
                        }

                        let estimate = PlonkSuccinctVerifier::<Bn256>::estimate_cost(&protocol);
                        for _ in 0..estimate.num_commitment {
                            transcript.write_ec_point(G1Affine::random(OsRng)).unwrap();
                        }
                        log::info!(
                            "{} {:#?} num_witness={} evalutations={} estimate={:#?}",
                            $LABEL,
                            CIRCUIT_CONFIG,
                            protocol.num_witness.len(),
                            protocol.evaluations.len(),
                            estimate
                        );

                        transcript.finalize()
                    } else {
                        gen_proof::<_, _, PoseidonTranscript<_, _>, PoseidonTranscript<_, _>, _>(
                            &params,
                            &keygen_pk(&params, vk, &circuit).expect("pk"),
                            circuit,
                            instance.clone(),
                            fixed_rng(),
                            true,
                            true,
                        )
                    };

                    (protocol, instance, proof)
                };

                let agg_params =
                    ProverParams::setup(CIRCUIT_CONFIG.min_k_aggregation as u32, fixed_rng());
                let agg_circuit = RootCircuit::new(
                    &agg_params,
                    &protocol,
                    Value::known(&instance),
                    Value::known(&proof),
                    false,
                )
                .expect("RootCircuit::new");

                let agg_vk = keygen_vk(&agg_params, &agg_circuit).expect("vk");

                let mut data = Verifier::default();
                data.label = format!("{}-{}-a", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                data.config = CIRCUIT_CONFIG;
                data.code = gen_verifier(
                    &agg_params,
                    &agg_vk,
                    Config::kzg()
                        .with_num_instance(agg_circuit.num_instance())
                        .with_accumulator_indices(Some(agg_circuit.accumulator_indices())),
                    agg_circuit.num_instance(),
                )
                .into();
                data.write_yul();
            },
            {
                panic!("no circuit parameters found");
            }
        );
    }};
}

// wrapper
macro_rules! gen {
    ($LABEL:expr, $CIRCUIT:ident, $GAS:expr) => {{
        fn func() {
            gen_match!($LABEL, $CIRCUIT, $GAS);
        }
        func();
    }};
}

macro_rules! for_each {
    ($LABEL:expr, $CIRCUIT:ident) => {{
        gen!($LABEL, $CIRCUIT, 63_000);
        gen!($LABEL, $CIRCUIT, 300_000);
    }};
}

#[test]
fn autogen_verifier_super() {
    for_each!("super", gen_super_circuit);
}

#[test]
fn autogen_verifier_pi() {
    for_each!("pi", gen_pi_circuit);
}
