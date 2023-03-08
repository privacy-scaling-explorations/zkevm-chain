use crate::circuit_witness::CircuitWitness;
use crate::circuits::*;
use crate::utils::collect_instance;
use crate::utils::fixed_rng;
use crate::utils::gen_num_instance;
use crate::utils::gen_proof;
use crate::Fr;
use crate::G1Affine;
use crate::ProverKey;
use crate::ProverParams;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::SerdeFormat;
use hyper::Uri;
use rand::{thread_rng, Rng};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use std::collections::HashMap;
use std::fmt::Write;
use std::fs::File;
use std::io::Write as IoWrite;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use zkevm_circuits::root_circuit::compile;
use zkevm_circuits::root_circuit::Config as PlonkConfig;
use zkevm_circuits::root_circuit::PoseidonTranscript;
use zkevm_circuits::root_circuit::RootCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_common::json_rpc::jsonrpc_request_client;
use zkevm_common::prover::*;

fn get_param_path(path: &String, k: usize) -> PathBuf {
    // try to automatically choose a file if the path is a folder.
    if Path::new(path).is_dir() {
        Path::new(path).join(format!("{k}.bin"))
    } else {
        Path::new(path).to_path_buf()
    }
}

fn get_or_gen_param(task_options: &ProofRequestOptions, k: usize) -> (Arc<ProverParams>, String) {
    match &task_options.param {
        Some(v) => {
            let path = get_param_path(v, k);
            let file = File::open(&path).expect("couldn't open params");
            let params = Arc::new(
                ProverParams::read(&mut std::io::BufReader::new(file))
                    .expect("Failed to read params"),
            );

            (params, path.to_str().unwrap().into())
        }
        None => {
            let param = ProverParams::setup(k as u32, fixed_rng());
            if std::env::var("PROVERD_DUMP").is_ok() {
                param
                    .write_custom(
                        &mut File::create(format!("params-{k}")).unwrap(),
                        SerdeFormat::RawBytesUnchecked,
                    )
                    .unwrap();
            }
            let param = Arc::new(param);
            (param, format!("{k}"))
        }
    }
}

async fn compute_proof<C: Circuit<Fr> + Clone + SubCircuit<Fr>>(
    shared_state: &SharedState,
    task_options: &ProofRequestOptions,
    circuit_config: CircuitConfig,
    circuit: C,
) -> Result<(CircuitConfig, ProofResult, ProofResult), String> {
    log::info!("Using circuit parameters: {:#?}", circuit_config);

    let mut circuit_proof = ProofResult {
        label: format!(
            "{}-{}",
            task_options.circuit, circuit_config.block_gas_limit
        ),
        ..Default::default()
    };
    let mut aggregation_proof = ProofResult {
        label: format!(
            "{}-{}-a",
            task_options.circuit, circuit_config.block_gas_limit
        ),
        ..Default::default()
    };

    if task_options.mock {
        // only run the mock prover
        let time_started = Instant::now();
        circuit_proof.k = circuit_config.min_k as u8;
        circuit_proof.instance = collect_instance(&circuit.instance());
        let prover = MockProver::run(circuit_config.min_k as u32, &circuit, circuit.instance())
            .expect("MockProver::run");
        prover.verify_par().expect("MockProver::verify_par");
        circuit_proof.aux.mock = Instant::now().duration_since(time_started).as_millis() as u32;
    } else {
        let (param, param_path) = get_or_gen_param(task_options, circuit_config.min_k);
        circuit_proof.k = param.k() as u8;
        // generate and cache the prover key
        let pk = {
            let cache_key = format!(
                "{}{}{:?}",
                &task_options.circuit, &param_path, &circuit_config
            );
            shared_state
                .gen_pk(&cache_key, &param, &circuit, &mut circuit_proof.aux)
                .await
                .map_err(|e| e.to_string())?
        };

        let circuit_instance = circuit.instance();
        circuit_proof.instance = collect_instance(&circuit_instance);

        if task_options.aggregate {
            let proof = gen_proof::<_, _, PoseidonTranscript<_, _>, PoseidonTranscript<_, _>, _>(
                &param,
                &pk,
                circuit,
                circuit_instance.clone(),
                fixed_rng(),
                task_options.mock_feedback,
                task_options.verify_proof,
                &mut circuit_proof.aux,
            );
            circuit_proof.proof = proof.clone().into();

            if std::env::var("PROVERD_DUMP").is_ok() {
                File::create(format!(
                    "proof-{}-{:?}",
                    task_options.circuit, &circuit_config
                ))
                .unwrap()
                .write_all(&proof)
                .unwrap();
            }

            // aggregate the circuit proof
            let protocol = {
                let time_started = Instant::now();
                let v = compile(
                    param.as_ref(),
                    pk.get_vk(),
                    PlonkConfig::kzg().with_num_instance(gen_num_instance(&circuit_instance)),
                );
                aggregation_proof.aux.protocol =
                    Instant::now().duration_since(time_started).as_millis() as u32;
                v
            };

            let (agg_params, agg_param_path) =
                get_or_gen_param(task_options, circuit_config.min_k_aggregation);
            aggregation_proof.k = agg_params.k() as u8;

            let agg_circuit = {
                let time_started = Instant::now();
                let v = RootCircuit::new(
                    &agg_params,
                    &protocol,
                    Value::known(&circuit_instance),
                    Value::known(&proof),
                )
                .expect("RootCircuit::new");
                aggregation_proof.aux.circuit =
                    Instant::now().duration_since(time_started).as_millis() as u32;
                v
            };

            let agg_pk = {
                let cache_key = format!(
                    "{}{}{:?}ag",
                    &task_options.circuit, &agg_param_path, &circuit_config
                );
                shared_state
                    .gen_pk(
                        &cache_key,
                        &agg_params,
                        &agg_circuit,
                        &mut aggregation_proof.aux,
                    )
                    .await
                    .map_err(|e| e.to_string())?
            };
            let agg_instance = agg_circuit.instance().to_vec();
            aggregation_proof.instance = collect_instance(&agg_instance);
            let proof = gen_proof::<
                _,
                _,
                EvmTranscript<G1Affine, _, _, _>,
                EvmTranscript<G1Affine, _, _, _>,
                _,
            >(
                agg_params.as_ref(),
                &agg_pk,
                agg_circuit,
                agg_instance,
                fixed_rng(),
                task_options.mock_feedback,
                task_options.verify_proof,
                &mut aggregation_proof.aux,
            );
            if std::env::var("PROVERD_DUMP").is_ok() {
                File::create(format!(
                    "proof-{}-agg--{:?}",
                    task_options.circuit, &circuit_config
                ))
                .unwrap()
                .write_all(&proof)
                .unwrap();
            }
            aggregation_proof.proof = proof.into();
        } else {
            let proof = gen_proof::<
                _,
                _,
                EvmTranscript<G1Affine, _, _, _>,
                EvmTranscript<G1Affine, _, _, _>,
                _,
            >(
                &param,
                &pk,
                circuit,
                circuit_instance.clone(),
                fixed_rng(),
                task_options.mock_feedback,
                task_options.verify_proof,
                &mut circuit_proof.aux,
            );
            circuit_proof.proof = proof.into();
        }
    }

    Ok((circuit_config, circuit_proof, aggregation_proof))
}

macro_rules! compute_proof_wrapper {
    ($shared_state:expr, $task_options:expr, $witness:expr, $CIRCUIT:ident) => {{
        let timing = Instant::now();
        let circuit = $CIRCUIT::<
            { CIRCUIT_CONFIG.max_txs },
            { CIRCUIT_CONFIG.max_calldata },
            { CIRCUIT_CONFIG.max_rws },
            { CIRCUIT_CONFIG.max_copy_rows },
            _,
        >(&$witness, fixed_rng())?;
        let timing = Instant::now().duration_since(timing).as_millis() as u32;
        let (circuit_config, mut circuit_proof, aggregation_proof) =
            compute_proof(&$shared_state, &$task_options, CIRCUIT_CONFIG, circuit).await?;
        circuit_proof.aux.circuit = timing;
        (circuit_config, circuit_proof, aggregation_proof)
    }};
}

#[derive(Clone)]
pub struct RoState {
    // a unique identifier
    pub node_id: String,
    // a `HOSTNAME:PORT` conformant string that will be used for DNS service discovery of other
    // nodes
    pub node_lookup: Option<String>,
}

pub struct RwState {
    pub tasks: Vec<ProofRequest>,
    pub pk_cache: HashMap<String, Arc<ProverKey>>,
    /// The current active task this instance wants to obtain or is working on.
    pub pending: Option<ProofRequestOptions>,
    /// `true` if this instance started working on `pending`
    pub obtained: bool,
}

#[derive(Clone)]
pub struct SharedState {
    pub ro: RoState,
    pub rw: Arc<Mutex<RwState>>,
}

impl SharedState {
    pub fn new(node_id: String, node_lookup: Option<String>) -> SharedState {
        Self {
            ro: RoState {
                node_id,
                node_lookup,
            },
            rw: Arc::new(Mutex::new(RwState {
                tasks: Vec::new(),
                pk_cache: HashMap::new(),
                pending: None,
                obtained: false,
            })),
        }
    }

    /// Will return the result or error of the task if it's completed.
    /// Otherwise enqueues the task and returns `None`.
    /// `retry_if_error` enqueues the task again if it returned with an error
    /// before.
    pub async fn get_or_enqueue(
        &self,
        options: &ProofRequestOptions,
    ) -> Option<Result<Proofs, String>> {
        let mut rw = self.rw.lock().await;

        // task already pending or completed?
        let task = rw.tasks.iter_mut().find(|e| e.options == *options);

        if task.is_some() {
            let mut task = task.unwrap();

            if task.result.is_some() {
                if options.retry && task.result.as_ref().unwrap().is_err() {
                    log::debug!("retrying: {:#?}", task);
                    // will be a candidate in `duty_cycle` again
                    task.result = None;
                    task.edition += 1;
                } else {
                    log::debug!("completed: {:#?}", task);
                    return task.result.clone();
                }
            } else {
                log::debug!("pending: {:#?}", task);
                return None;
            }
        } else {
            // enqueue the task
            let task = ProofRequest {
                options: options.clone(),
                result: None,
                edition: 0,
            };
            log::debug!("enqueue: {:#?}", task);
            rw.tasks.push(task);
        }

        None
    }

    /// Checks if there is anything to do like:
    /// - records if a task completed
    /// - starting a new task
    /// Blocks until completion but releases the lock of `self.rw` in between.
    pub async fn duty_cycle(&self) {
        // fix the 'world' view
        if let Err(err) = self.merge_tasks_from_peers().await {
            log::error!("merge_tasks_from_peers failed with: {}", err);
            return;
        }

        let rw = self.rw.lock().await;
        if rw.pending.is_some() || rw.obtained {
            // already computing
            return;
        }
        // find a pending task
        let tasks: Vec<ProofRequestOptions> = rw
            .tasks
            .iter()
            .filter(|&e| e.result.is_none())
            .map(|e| e.options.clone())
            .collect();
        drop(rw);

        for task in tasks {
            // signals that this node wants to process this task
            log::debug!("trying to obtain {:#?}", task);
            self.rw.lock().await.pending = Some(task);

            // notify other peers
            // wrap the object because it's important to clear `pending` on error
            {
                let self_copy = self.clone();
                let obtain_task =
                    tokio::spawn(
                        async move { self_copy.obtain_task().await.expect("obtain_task") },
                    )
                    .await;

                if obtain_task.is_err() || !obtain_task.unwrap() {
                    self.rw.lock().await.pending = None;
                    log::debug!("failed to obtain task");
                    continue;
                }

                // won the race
                self.rw.lock().await.obtained = true;
                break;
            }
        }

        // needs to be cloned because of long running tasks and
        // the possibility that the task gets removed in the meantime
        let task_options = self.rw.lock().await.pending.clone();
        if task_options.is_none() {
            // nothing to do
            return;
        }

        // succesfully obtained the task
        let task_options = task_options.unwrap();
        log::info!("compute_proof: {:#?}", task_options);

        // Note: this catches any panics for the task itself but will not help in the
        // situation when the process get itself OOM killed, stack overflows etc.
        // This could be avoided by spawning a subprocess for the proof computation
        // instead.

        // spawn a task to catch panics
        let task_result: Result<Result<Proofs, String>, tokio::task::JoinError> = {
            let task_options_copy = task_options.clone();
            let self_copy = self.clone();

            tokio::spawn(async move {
                let witness =
                    CircuitWitness::from_rpc(&task_options_copy.block, &task_options_copy.rpc)
                        .await
                        .map_err(|e| e.to_string())?;

                let (config, circuit_proof, aggregation_proof) = crate::match_circuit_params!(
                    witness.gas_used(),
                    {
                        match task_options_copy.circuit.as_str() {
                            "pi" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_pi_circuit
                                )
                            }
                            "super" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_super_circuit
                                )
                            }
                            "evm" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_evm_circuit
                                )
                            }
                            "state" => compute_proof_wrapper!(
                                self_copy,
                                task_options_copy,
                                &witness,
                                gen_state_circuit
                            ),
                            "tx" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_tx_circuit
                                )
                            }
                            "bytecode" => compute_proof_wrapper!(
                                self_copy,
                                task_options_copy,
                                &witness,
                                gen_bytecode_circuit
                            ),
                            "copy" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_copy_circuit
                                )
                            }
                            "exp" => {
                                compute_proof_wrapper!(
                                    self_copy,
                                    task_options_copy,
                                    &witness,
                                    gen_exp_circuit
                                )
                            }
                            "keccak" => compute_proof_wrapper!(
                                self_copy,
                                task_options_copy,
                                &witness,
                                gen_keccak_circuit
                            ),
                            _ => panic!("unknown circuit"),
                        }
                    },
                    {
                        return Err(format!(
                            "No circuit parameters found for block with gas used={}",
                            witness.gas_used()
                        ));
                    }
                );

                let res = Proofs {
                    config,
                    circuit: circuit_proof,
                    aggregation: aggregation_proof,
                    gas: witness.gas_used(),
                };

                Ok(res)
            })
            .await
        };

        // convert the JoinError to string - if applicable
        let task_result: Result<Proofs, String> = match task_result {
            Err(err) => match err.is_panic() {
                true => {
                    let panic = err.into_panic();

                    if let Some(msg) = panic.downcast_ref::<&str>() {
                        Err(msg.to_string())
                    } else if let Some(msg) = panic.downcast_ref::<String>() {
                        Err(msg.to_string())
                    } else {
                        Err("unknown panic".to_string())
                    }
                }
                false => Err(err.to_string()),
            },
            Ok(val) => val,
        };

        {
            // done, update the queue
            log::info!("task_result: {:#?}", task_result);

            let mut rw = self.rw.lock().await;
            // clear fields
            rw.pending = None;
            rw.obtained = false;
            // insert task result
            let task = rw.tasks.iter_mut().find(|e| e.options == task_options);
            if let Some(task) = task {
                // found our task, update result
                task.result = Some(task_result);
                task.edition += 1;
            } else {
                // task was already removed in the meantime,
                // assume it's obsolete and forget about it
                log::info!(
                    "task was already removed, ignoring result {:#?}",
                    task_options
                );
            }
        }
    }

    /// Returns `node_id` and `tasks` for this instance.
    /// Normally used for the rpc api.
    pub async fn get_node_information(&self) -> NodeInformation {
        NodeInformation {
            id: self.ro.node_id.clone(),
            tasks: self.rw.lock().await.tasks.clone(),
        }
    }

    /// Pulls `NodeInformation` from all other peers and
    /// merges missing or updated tasks from these peers to
    /// preserve information in case individual nodes are going to be
    /// terminated.
    ///
    /// Always returns `true` otherwise returns with error.
    pub async fn merge_tasks_from_peers(&self) -> Result<bool, String> {
        const LOG_TAG: &str = "merge_tasks_from_peers:";

        if self.ro.node_lookup.is_none() {
            return Ok(true);
        }

        let hyper_client = hyper::Client::new();
        let addrs_iter = self
            .ro
            .node_lookup
            .as_ref()
            .unwrap()
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;

        for addr in addrs_iter {
            let uri = Uri::try_from(format!("http://{addr}")).map_err(|e| e.to_string())?;
            let peer: NodeInformation =
                jsonrpc_request_client(5000, &hyper_client, &uri, "info", serde_json::json!([]))
                    .await?;

            if peer.id == self.ro.node_id {
                log::debug!("{} skipping self({})", LOG_TAG, peer.id);
                continue;
            }

            log::debug!("{} merging with peer({})", LOG_TAG, peer.id);
            self.merge_tasks(&peer).await;
        }

        Ok(true)
    }

    // TODO: can this be pre-generated to a file?
    // related
    // https://github.com/zcash/halo2/issues/443
    // https://github.com/zcash/halo2/issues/449
    /// Compute or retrieve a proving key from cache.
    async fn gen_pk<C: Circuit<Fr>>(
        &self,
        cache_key: &str,
        param: &Arc<ProverParams>,
        circuit: &C,
        aux: &mut ProofResultInstrumentation,
    ) -> Result<Arc<ProverKey>, Box<dyn std::error::Error>> {
        let mut rw = self.rw.lock().await;
        if !rw.pk_cache.contains_key(cache_key) {
            // drop, potentially long running
            drop(rw);

            let vk = {
                let time_started = Instant::now();
                let vk = keygen_vk(param.as_ref(), circuit)?;
                aux.vk = Instant::now().duration_since(time_started).as_millis() as u32;
                vk
            };
            let pk = {
                let time_started = Instant::now();
                let pk = keygen_pk(param.as_ref(), vk, circuit)?;
                aux.pk = Instant::now().duration_since(time_started).as_millis() as u32;
                pk
            };
            if std::env::var("PROVERD_DUMP").is_ok() {
                pk.write(
                    &mut File::create(cache_key).unwrap(),
                    SerdeFormat::RawBytesUnchecked,
                )
                .unwrap();
            }

            let pk = Arc::new(pk);

            // acquire lock and update
            rw = self.rw.lock().await;
            rw.pk_cache.insert(cache_key.to_string(), pk);

            log::info!("ProvingKey: generated and cached key={}", cache_key);
        }

        Ok(rw.pk_cache.get(cache_key).unwrap().clone())
    }

    async fn merge_tasks(&self, node_info: &NodeInformation) {
        const LOG_TAG: &str = "merge_tasks:";
        let mut rw = self.rw.lock().await;

        for peer_task in &node_info.tasks {
            let maybe_task = rw.tasks.iter_mut().find(|e| e.options == peer_task.options);

            if let Some(existent_task) = maybe_task {
                if existent_task.edition >= peer_task.edition {
                    // fast case
                    log::debug!("{} up to date {:#?}", LOG_TAG, existent_task);
                    continue;
                }

                // update result, edition
                existent_task.edition = peer_task.edition;
                existent_task.result = peer_task.result.clone();
                log::debug!("{} updated {:#?}", LOG_TAG, existent_task);
            } else {
                // copy task
                rw.tasks.push(peer_task.clone());
                log::debug!("{} new task {:#?}", LOG_TAG, peer_task);
            }
        }
    }

    /// Tries to obtain `self.rw.pending` by querying all other peers
    /// about their current task item that resolves to either
    /// winning or losing the task depending on the algorithm.
    ///
    /// Expects `self.rw.pending` to be not `None`
    async fn obtain_task(&self) -> Result<bool, String> {
        const LOG_TAG: &str = "obtain_task:";

        let task_options = self
            .rw
            .lock()
            .await
            .pending
            .as_ref()
            .expect("pending task")
            .clone();

        if self.ro.node_lookup.is_none() {
            return Ok(true);
        }

        // resolve all other nodes for this service
        let hyper_client = hyper::Client::new();
        let addrs_iter = self
            .ro
            .node_lookup
            .as_ref()
            .unwrap()
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        for addr in addrs_iter {
            let uri = Uri::try_from(format!("http://{addr}")).map_err(|e| e.to_string())?;
            let peer: NodeStatus =
                jsonrpc_request_client(5000, &hyper_client, &uri, "status", serde_json::json!([]))
                    .await?;

            if peer.id == self.ro.node_id {
                log::debug!("{} skipping self({})", LOG_TAG, peer.id);
                continue;
            }

            if let Some(peer_task) = peer.task {
                if peer_task == task_options {
                    // a slight chance to 'win' the task
                    if !peer.obtained && peer.id > self.ro.node_id {
                        log::debug!("{} won task against {}", LOG_TAG, peer.id);
                        // continue the race against the remaining peers
                        continue;
                    }

                    log::debug!("{} lost task against {}", LOG_TAG, peer.id);
                    // early return
                    return Ok(false);
                }
            }
        }

        // default
        Ok(true)
    }

    pub fn random_worker_id() -> String {
        // derive a (sufficiently large) random worker id
        const N: usize = 16;
        let mut arr = [0u8; N];
        thread_rng().fill(&mut arr[..]);
        let mut node_id = String::with_capacity(N * 2);
        for byte in arr {
            write!(node_id, "{byte:02x}").unwrap();
        }

        node_id
    }
}
