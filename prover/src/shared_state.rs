use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::bn256::G1Affine;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::Blake2bWrite;
use halo2_proofs::transcript::Challenge255;

use std::collections::HashMap;
use std::env::var;
use std::fmt::Write;
use std::fs::File;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Instant;

use eth_types::Bytes;
use hyper::Uri;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use tokio::sync::Mutex;

use crate::compute_proof::*;
use crate::json_rpc::jsonrpc_request_client;
use crate::structs::*;

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
    pub params_cache: HashMap<String, Arc<Params<G1Affine>>>,
    pub pk_cache: HashMap<String, Arc<ProvingKey<G1Affine>>>,
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
                params_cache: HashMap::new(),
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
        let task_options_copy = task_options.clone();
        let self_copy = self.clone();
        let task_result: Result<Result<Proofs, String>, tokio::task::JoinError> =
            tokio::spawn(async move {
                let (block, txs, gas_used) =
                    gen_block_witness(&task_options_copy.block, &task_options_copy.rpc)
                        .await
                        .map_err(|e| e.to_string())?;

                let (evm_proof, k_used, duration) = crate::match_circuit_params!(
                    gas_used,
                    {
                        log::info!(
                            "Using circuit parameters: BLOCK_GAS_LIMIT={} MAX_TXS={} MAX_CALLDATA={} MAX_BYTECODE={} MIN_K={} STATE_CIRCUIT_PAD_TO={}",
                            BLOCK_GAS_LIMIT, MAX_TXS, MAX_CALLDATA, MAX_BYTECODE, MIN_K, STATE_CIRCUIT_PAD_TO
                        );

                        // try to automatically choose a file if the path ends with a `/`.
                        let param_path = match task_options_copy.param.ends_with('/') {
                            true => format!("{}{}.bin", task_options_copy.param, MIN_K),
                            false => task_options_copy.param,
                        };

                        // lazily load the file and cache it.
                        // Note: we are not validating it for `MIN_K`,
                        // this error will eventually bubble up later.
                        let param = self_copy.load_param(&param_path).await;
                        // generate and cache the prover key
                        let pk = self_copy.gen_pk::<MAX_TXS, MAX_CALLDATA>(
                            &param_path,
                            BLOCK_GAS_LIMIT,
                            MAX_BYTECODE,
                            STATE_CIRCUIT_PAD_TO,
                        ).await
                        .map_err(|e| e.to_string())?;

                        let time_started = Instant::now();

                        let instance = match var("PROVERD_ENABLE_CIRCUIT_INSTANCE").unwrap_or_default().as_str() {
                            "" | "0" | "false" => vec![],
                            _ => {
                                use zkevm_circuits::tx_circuit::POW_RAND_SIZE;
                                use halo2_proofs::arithmetic::BaseExt;
                                // TODO: This should come from the circuit `circuit.instance()`.
                                let mut instance: Vec<Vec<Fr>>= (1..POW_RAND_SIZE + 1)
                                    .map(|exp| vec![block.randomness.pow(&[exp as u64, 0, 0, 0]); param.n as usize - 64])
                                    .collect();
                                // SignVerifyChip -> ECDSAChip -> MainGate instance column
                                instance.push(vec![]);

                                instance
                            }
                        };
                        let instance: Vec<&[Fr]> = instance.iter().map(|e| e.as_slice()).collect();
                        let instances = match instance.is_empty() {
                            true => vec![],
                            false => vec![instance.as_slice()],
                        };

                        let circuit =
                            gen_circuit::<MAX_TXS, MAX_CALLDATA>(MAX_BYTECODE, block, txs)?;
                        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                        create_proof(&param, &pk, &[circuit], &instances, OsRng, &mut transcript)
                            .map_err(|e| e.to_string())?;

                        (transcript.finalize(), param.k, Instant::now().duration_since(time_started).as_millis())
                    },
                    {
                        return Err(format!("No circuit parameters found for block with gas used={}", gas_used));
                    }
                );
                let res = Proofs {
                    evm_proof: evm_proof.into(),
                    state_proof: Bytes::default(),
                    duration: duration as u64,
                    k: k_used as u8,
                };

                Ok(res)
            })
            .await;

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
            let uri = Uri::try_from(format!("http://{}", addr)).map_err(|e| e.to_string())?;
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

    async fn load_param(&self, params_path: &str) -> Arc<Params<G1Affine>> {
        let mut rw = self.rw.lock().await;

        if !rw.params_cache.contains_key(params_path) {
            // drop, potentially long running
            drop(rw);

            // load polynomial commitment parameters
            let params_fs = File::open(params_path).expect("couldn't open params");
            let params: Arc<Params<G1Affine>> = Arc::new(
                Params::read::<_>(&mut std::io::BufReader::new(params_fs))
                    .expect("Failed to read params"),
            );

            // acquire lock and update
            rw = self.rw.lock().await;
            rw.params_cache.insert(params_path.to_string(), params);

            log::info!("params: initialized {}", params_path);
        }

        rw.params_cache.get(params_path).unwrap().clone()
    }

    async fn gen_pk<const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        &self,
        params_path: &str,
        block_gas_limit: usize,
        max_bytecode: usize,
        state_circuit_pad_to: usize,
    ) -> Result<Arc<ProvingKey<G1Affine>>, Box<dyn std::error::Error>> {
        let cache_key = format!(
            "{}{}{}{}{}{}",
            params_path, MAX_TXS, MAX_CALLDATA, block_gas_limit, max_bytecode, state_circuit_pad_to
        );
        let mut rw = self.rw.lock().await;
        if !rw.pk_cache.contains_key(&cache_key) {
            // drop, potentially long running
            drop(rw);

            let param = self.load_param(params_path).await;
            let pk = gen_static_key::<MAX_TXS, MAX_CALLDATA>(
                &param,
                block_gas_limit,
                max_bytecode,
                state_circuit_pad_to,
            )?;
            let pk = Arc::new(pk);

            // acquire lock and update
            rw = self.rw.lock().await;
            rw.pk_cache.insert(cache_key.clone(), pk);

            log::info!("ProvingKey: generated and cached key={}", cache_key);
        }

        Ok(rw.pk_cache.get(&cache_key).unwrap().clone())
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
            let uri = Uri::try_from(format!("http://{}", addr)).map_err(|e| e.to_string())?;
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
}

impl Default for SharedState {
    /// The default setup a random `node_id` and expects a
    /// - `PROVERD_LOOKUP`
    ///   - environment variable in the form of HOSTNAME:PORT
    fn default() -> Self {
        // derive a (sufficiently large) random worker id
        const N: usize = 16;
        let mut arr = [0u8; N];
        thread_rng().fill(&mut arr[..]);
        let mut node_id = String::with_capacity(N * 2);
        for byte in arr {
            write!(node_id, "{:02x}", byte).unwrap();
        }

        let addr: String = var("PROVERD_LOOKUP").expect("PROVERD_LOOKUP env var");

        Self::new(node_id, Some(addr))
    }
}
