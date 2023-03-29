use crate::config::Config;
use crate::structs::*;
use crate::utils::*;
use ethers_core::abi::Abi;
use ethers_core::abi::AbiParser;
use ethers_core::abi::RawLog;
use ethers_core::abi::Token;
use ethers_core::abi::Tokenizable;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::{
    Address, Block, Bytes, Filter, Log, Transaction, TransactionRequest, TxpoolStatus,
    ValueOrArray, H256, U256, U64,
};
use ethers_core::utils::keccak256;
use ethers_core::utils::rlp;
use ethers_signers::LocalWallet;
use ethers_signers::Signer;
use hyper::client::HttpConnector;
use hyper::Uri;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cmp;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;
use zkevm_common::json_rpc::jsonrpc_request;
use zkevm_common::json_rpc::jsonrpc_request_client;
use zkevm_common::prover::ProofRequestOptions;
use zkevm_common::prover::Proofs;

pub struct RoState {
    pub l2_message_deliverer_addr: Address,
    pub l2_message_dispatcher_addr: Address,

    pub block_beacon_topic: H256,
    pub block_finalized_topic: H256,
    pub message_dispatched_topic: H256,
    pub message_delivered_topic: H256,

    pub http_client: hyper::Client<HttpConnector>,
    pub l1_wallet: LocalWallet,
    pub l2_wallet: LocalWallet,

    pub bridge_abi: Abi,
}

impl RoState {
    pub async fn new(config: &Config) -> Self {
        let l1_wallet = get_wallet(&config.l1_rpc_url, &config.l1_priv).await;
        // TODO: support different keys for L1 and L2
        let l2_wallet = get_wallet(&config.l2_rpc_url, &config.l1_priv).await;

        let abi = get_abi();

        let beacon_topic = abi.event("BlockSubmitted").unwrap().signature();
        let block_finalized_topic = abi.event("BlockFinalized").unwrap().signature();
        let message_dispatched_topic = abi.event("MessageDispatched").unwrap().signature();
        let message_delivered_topic = abi.event("MessageDelivered").unwrap().signature();

        RoState {
            l2_message_deliverer_addr: "0x0000000000000000000000000000000000010000"
                .parse()
                .unwrap(),
            l2_message_dispatcher_addr: "0x0000000000000000000000000000000000020000"
                .parse()
                .unwrap(),

            block_beacon_topic: beacon_topic,
            block_finalized_topic,
            message_dispatched_topic,
            message_delivered_topic,

            http_client: hyper::Client::new(),
            l1_wallet,
            l2_wallet,
            bridge_abi: abi,
        }
    }
}

pub struct RwState {
    pub chain_state: ForkchoiceStateV1,
    pub nodes: Vec<Uri>,
    pub prover_requests: HashMap<U64, Option<Proofs>>,
    pub pending_proofs: u32,
    pub l1_last_sync_block: U64,
    pub l2_last_sync_block: U64,
    pub l1_message_queue: VecDeque<MessageBeacon>,
    pub l2_delivered_messages: Vec<H256>,
    pub l2_message_queue: Vec<MessageBeacon>,
    pub l1_delivered_messages: Vec<H256>,

    /// keeps track of the timestamp used for preparing the last block
    _prev_timestamp: u64,
}

impl Default for RwState {
    fn default() -> Self {
        RwState {
            chain_state: ForkchoiceStateV1 {
                head_block_hash: H256::zero(),
                safe_block_hash: H256::zero(),
                finalized_block_hash: H256::zero(),
            },
            nodes: Vec::new(),
            prover_requests: HashMap::new(),
            pending_proofs: 0,
            l1_last_sync_block: U64::zero(),
            l2_last_sync_block: U64::zero(),
            l1_message_queue: VecDeque::new(),
            l2_delivered_messages: Vec::new(),
            l2_message_queue: Vec::new(),
            l1_delivered_messages: Vec::new(),

            _prev_timestamp: 0,
        }
    }
}

#[derive(Clone)]
pub struct SharedState {
    pub config: Arc<Mutex<Config>>,
    pub ro: Arc<RoState>,
    pub rw: Arc<Mutex<RwState>>,
}

impl SharedState {
    pub async fn new(config: &Config) -> Self {
        Self {
            config: Arc::new(Mutex::new(config.clone())),
            ro: Arc::new(RoState::new(config).await),
            rw: Arc::new(Mutex::new(RwState::default())),
        }
    }

    /// Initiates configuration from environment variables only.
    pub async fn from_env() -> Self {
        let config = Config::from_env();

        Self::new(&config).await
    }

    pub async fn init(&self) {
        if !self.rw.lock().await.chain_state.head_block_hash.is_zero() {
            panic!("init");
        }

        let genesis: Block<H256> = self
            .request_l2("eth_getBlockByNumber", ("0x0", false))
            .await
            .expect("genesis block");
        let h = genesis.hash.unwrap();
        log::info!("init with genesis: {:?}", h);

        let chain_state = &mut self.rw.lock().await.chain_state;
        chain_state.head_block_hash = h;
        chain_state.safe_block_hash = h;
        chain_state.finalized_block_hash = h;

        // initialize l1 bridge if necessary
        let bridge_state_root = self
            .call_fn_l1("stateRoots", &[genesis.hash.unwrap().into_token()])
            .await
            .expect("l1.stateRoots");
        if bridge_state_root == H256::zero() {
            log::info!("init l1 bridge");
            let block_hash = genesis.hash.unwrap();
            let state_root = genesis.state_root;
            let calldata = get_abi()
                .function("initGenesis")
                .unwrap()
                .encode_input(&[block_hash.into_token(), state_root.into_token()])
                .expect("calldata");
            let l1_bridge_addr = self.config.lock().await.l1_bridge;
            self.transaction_to_l1(Some(l1_bridge_addr), U256::zero(), calldata)
                .await
                .expect("init genesis");
        }
    }

    pub async fn sync(&self) {
        // sync events
        let latest_block: U64 = self
            .request_l1("eth_blockNumber", ())
            .await
            .expect("eth_blockNumber");
        let mut last_to_block: U64 = U64::zero();
        let mut from: U64 = self.rw.lock().await.l1_last_sync_block + 1;
        let mut filter = Filter::new()
            .address(ValueOrArray::Value(self.config.lock().await.l1_bridge))
            .topic0(ValueOrArray::Array(vec![
                self.ro.block_beacon_topic,
                self.ro.block_finalized_topic,
                self.ro.message_dispatched_topic,
                self.ro.message_delivered_topic,
            ]));

        while from <= latest_block {
            // TODO: increase or decrease request range depending on fetch success
            let to = cmp::min(from + 1u64, latest_block);
            log::trace!("fetching l1 logs from={} to={}", from, to);
            filter = filter.from_block(from).to_block(to);

            let logs: Vec<Log> = self
                .request_l1("eth_getLogs", [&filter])
                .await
                .expect("eth_getLogs");
            // TODO: ugly hack to fix geth inconstency issues
            if !logs.is_empty() {
                last_to_block = to;
            }

            for log in logs {
                let topic = log.topics[0];

                if topic == self.ro.block_beacon_topic {
                    let tx_hash = log.transaction_hash.expect("log txhash");
                    let tx: Transaction = self
                        .request_l1("eth_getTransactionByHash", [tx_hash])
                        .await
                        .expect("tx");

                    let tx_data = tx.input.as_ref();

                    // TODO: handle the case if len < 68
                    let len = U256::from(&tx_data[36..68]).as_usize();
                    let start = 68;
                    let end = start + len;
                    if end > tx_data.len() {
                        log::warn!("TODO: zeropad block data");
                    }
                    let rlp = rlp::Rlp::new(&tx_data[start..end]);
                    let info = rlp.payload_info().expect("payload_info");
                    let block_header = &rlp.as_raw()[0..info.header_len + info.value_len];
                    let block_hash = H256::from(keccak256(block_header));
                    log::info!("BlockSubmitted: {:?} via {:?}", block_hash, tx_hash);

                    let resp: Result<serde_json::Value, String> =
                        self.request_l2("eth_getHeaderByHash", [block_hash]).await;

                    if resp.is_err() {
                        log::error!(
                            "TODO: block not found {} {}",
                            block_hash,
                            resp.err().unwrap()
                        );
                    }

                    self.rw.lock().await.chain_state.safe_block_hash = block_hash;
                    continue;
                }

                if topic == self.ro.block_finalized_topic {
                    let block_hash = H256::from_slice(log.data.as_ref());
                    log::info!(
                        "BlockFinalized: {:?} via {:?}",
                        block_hash,
                        log.transaction_hash
                    );

                    self.rw.lock().await.chain_state.finalized_block_hash = block_hash;
                    self.record_l2_messages(block_hash).await;
                    continue;
                }

                if topic == self.ro.message_dispatched_topic {
                    let beacon = self._parse_message_beacon(log);
                    log::info!("L1:MessageDispatched:{:?}", beacon.id);
                    log::debug!("{:?}", beacon);
                    self.rw.lock().await.l1_message_queue.push_back(beacon);
                    continue;
                }

                if topic == self.ro.message_delivered_topic {
                    let id = H256::from_slice(log.data.as_ref());
                    log::info!("L1:MessageDelivered:{:?}", id);
                    self.rw.lock().await.l1_delivered_messages.push(id);
                    continue;
                }
            }

            from = to + 1u64;
        }

        if last_to_block != U64::zero() {
            self.rw.lock().await.l1_last_sync_block = last_to_block;
        }
        self.sync_l2().await;
    }

    pub async fn mine(&self) {
        // TODO: verify that head_hash is correct
        let head_hash = get_chain_head(&self.ro.http_client, &self.config.lock().await.l2_rpc_url)
            .await
            .hash;
        self.rw.lock().await.chain_state.head_block_hash = head_hash;

        {
            // always send a miner_init request to enable transaction pool etc.
            // just to account for the case that the node was restarted
            let _: Option<Address> = self.request_l2("miner_init", ()).await.unwrap_or_default();
        }

        {
            // check l1 > l2 message queue
            let len = self.rw.lock().await.l1_message_queue.len();
            if len > 0 {
                let mut nonce: U256 = self
                    .request_l2(
                        "eth_getTransactionCount",
                        (self.ro.l2_wallet.address(), "latest"),
                    )
                    .await
                    .expect("nonce");

                const LOG_TAG: &str = "L2:deliverMessage:";

                // anchors a L1 block into L2
                let l1_block_header: BlockHeader = self
                    .request_l1("eth_getHeaderByNumber", ["latest"])
                    .await
                    .expect("l1 block header");
                // TODO: figure out how to get by hash - gonna be safer
                // Or just hash it and compare against l1_block_header.hash.
                let block_data: Bytes = self
                    .request_l1("debug_getHeaderRlp", [l1_block_header.number.as_u64()])
                    .await
                    .expect("block_data");
                let account_proof: Bytes = {
                    let l1_bridge_addr = self.config.lock().await.l1_bridge;
                    let proof_obj: ProofRequest = self
                        .request_l1("eth_getProof", (l1_bridge_addr, (), l1_block_header.hash))
                        .await
                        .expect("eth_getProof");
                    Bytes::from(marshal_proof_single(&proof_obj.account_proof))
                };
                let mut messages = Vec::new();
                // authorize l1 block
                {
                    let calldata = self
                        .ro
                        .bridge_abi
                        .function("importForeignBlock")
                        .unwrap()
                        .encode_input(&[
                            U256::from(l1_block_header.number.as_u64()).into_token(),
                            l1_block_header.hash.into_token(),
                        ])
                        .expect("calldata");
                    let tx = self
                        .sign_l2(
                            Some(self.ro.l2_message_deliverer_addr),
                            U256::zero(),
                            nonce,
                            calldata,
                        )
                        .await;
                    messages.push(tx);
                    nonce = nonce + 1;
                }
                // Use this block to run the messages against.
                // This is required for proper gas calculation.
                let block_timestamp = self.next_timestamp().await;
                let temporary_block = self
                    .prepare_block(block_timestamp, Some(&messages))
                    .await
                    .expect("prepare block with import tx");
                // import block header
                {
                    let calldata = self
                        .ro
                        .bridge_abi
                        .function("importForeignBridgeState")
                        .unwrap()
                        .encode_input(&[block_data.into_token(), account_proof.into_token()])
                        .expect("calldata");
                    let tx = self
                        .sign_l2_given_block_tag(
                            Some(self.ro.l2_message_deliverer_addr),
                            U256::zero(),
                            nonce,
                            calldata,
                            Some(format!("{:#066x}", temporary_block.hash.unwrap())),
                        )
                        .await
                        .expect("importForeignBridgeState on temporary_block");
                    messages.push(tx);
                    nonce = nonce + 1;
                }
                let mut temporary_block = self
                    .prepare_block(block_timestamp, Some(&messages))
                    .await
                    .expect("prepare block with import tx");
                let ts = U256::from(block_timestamp);
                let mut drop_idxs = Vec::new();
                let mut i = 0;
                let l1_bridge_addr = self.config.lock().await.l1_bridge;
                loop {
                    let rw = self.rw.lock().await;
                    let msg = rw.l1_message_queue.get(i);
                    if msg.is_none() {
                        break;
                    }
                    let msg = msg.unwrap().clone();
                    drop(rw);

                    if msg.deadline < ts {
                        log::info!("{} {:?} deadline exceeded", LOG_TAG, msg.id);
                        log::debug!("{:?}", msg);
                        drop_idxs.push(i);
                        i += 1;
                        continue;
                    }

                    {
                        let found = self
                            .rw
                            .lock()
                            .await
                            .l2_delivered_messages
                            .iter()
                            .any(|&e| e == msg.id);

                        log::info!("{} skip={} {:?}", LOG_TAG, found, msg.id);
                        log::debug!("{:?}", msg);

                        if found {
                            drop_idxs.push(i);
                            i += 1;
                            continue;
                        }
                    }

                    let storage_proof: Bytes = {
                        // calculate the storage slot for this message
                        let storage_slot = msg.storage_slot();
                        // request proof
                        let proof_obj: ProofRequest = self
                            .request_l1(
                                "eth_getProof",
                                (l1_bridge_addr, [storage_slot], l1_block_header.hash),
                            )
                            .await
                            .expect("eth_getProof");
                        // encode proof
                        Bytes::from(marshal_proof_single(&proof_obj.storage_proof[0].proof))
                    };
                    let calldata = self
                        .ro
                        .bridge_abi
                        .function("deliverMessageWithProof")
                        .unwrap()
                        .encode_input(&[
                            msg.from.into_token(),
                            msg.to.into_token(),
                            msg.value.into_token(),
                            msg.fee.into_token(),
                            msg.deadline.into_token(),
                            msg.nonce.into_token(),
                            Token::Bytes(msg.calldata),
                            storage_proof.into_token(),
                        ])
                        .expect("calldata");

                    // simulate against temporary block
                    let tx = self
                        .sign_l2_given_block_tag(
                            Some(self.ro.l2_message_deliverer_addr),
                            U256::zero(),
                            nonce,
                            calldata,
                            Some(format!("{:#066x}", temporary_block.hash.unwrap())),
                        )
                        .await;
                    if let Err(err) = tx {
                        log::debug!("{} simulate tx {}", LOG_TAG, err);
                        drop_idxs.push(i);
                        i += 1;
                        continue;
                    }

                    // try to build that block
                    messages.push(tx.unwrap());
                    let tmp = self.prepare_block(block_timestamp, Some(&messages)).await;
                    if let Err(err) = tmp {
                        log::debug!("{} {}", LOG_TAG, err);
                        // bad tx
                        messages.pop();

                        match err.as_str() {
                            "gas limit reached" => {
                                // block is full
                                break;
                            }
                            _ => {
                                // another error, probably a revert
                                drop_idxs.push(i);
                                i += 1;
                                continue;
                            }
                        }
                    }

                    // block looks good
                    temporary_block = tmp.unwrap();
                    log::debug!(
                        "{} used={} limit={}",
                        LOG_TAG,
                        temporary_block.gas_used,
                        temporary_block.gas_limit
                    );
                    nonce = nonce + 1;
                    drop_idxs.push(i);
                    i += 1;
                }

                // final step
                if temporary_block.transactions.len() > 1 {
                    self.set_chain_head(temporary_block.hash.unwrap())
                        .await
                        .expect("set_chain_head relay");
                }

                // everything went well
                let mut rw = self.rw.lock().await;
                for (i, original_pos) in drop_idxs.into_iter().enumerate() {
                    rw.l1_message_queue.remove(original_pos - i);
                }
            }
        }

        // check if we can mine a block
        let resp: TxpoolStatus = self.request_l2("txpool_status", ()).await.unwrap();
        let pending_txs = resp.pending.as_u64();

        if pending_txs != 0 {
            self.mine_block(None).await.expect("mine_block regular");
        }
    }

    pub async fn submit_blocks(&self) {
        // block submission
        let safe_hash = self.rw.lock().await.chain_state.safe_block_hash;
        let head_hash = self.rw.lock().await.chain_state.head_block_hash;
        if safe_hash != head_hash {
            // find all the blocks since `safe_hash`
            let blocks = get_blocks_between(
                &self.ro.http_client,
                &self.config.lock().await.l2_rpc_url,
                &safe_hash,
                &head_hash,
            )
            .await;
            let l1_bridge_addr = Some(self.config.lock().await.l1_bridge);

            log::trace!("blocks to be submitted: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                log::info!("submit_block: {}", format_block(block));
                {
                    let witness = self
                        .request_witness(&block.number.unwrap())
                        .await
                        .expect("witness");
                    let block_data = witness.input;
                    let calldata = self
                        .ro
                        .bridge_abi
                        .function("submitBlock")
                        .unwrap()
                        .encode_input(&[block_data.into_token()])
                        .expect("calldata");

                    self.transaction_to_l1(l1_bridge_addr, U256::zero(), calldata)
                        .await
                        .expect("receipt");
                }
            }
        }
    }

    pub async fn finalize_blocks(&self) -> Result<(), String> {
        // block finalization
        let safe_hash = self.rw.lock().await.chain_state.safe_block_hash;
        let final_hash = self.rw.lock().await.chain_state.finalized_block_hash;
        if final_hash != safe_hash {
            let blocks = get_blocks_between(
                &self.ro.http_client,
                &self.config.lock().await.l2_rpc_url,
                &final_hash,
                &safe_hash,
            )
            .await;

            log::trace!("blocks for finalization: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                self.finalize_block(block).await?;
            }
        }

        Ok(())
    }

    pub async fn finalize_block(&self, block: &Block<H256>) -> Result<(), String> {
        const LOG_TAG: &str = "L1:finalize_block:";
        log::trace!("{} {}", LOG_TAG, format_block(block));

        let block_num = block.number.unwrap();
        let proofs: Result<Option<Proofs>, String> = self.request_proof(&block_num).await;

        if let Err(err) = proofs {
            log::error!("{}:{} {:?}", LOG_TAG, block_num, err);

            return Err(err);
        }

        match proofs.unwrap() {
            None => log::trace!("{} proof not yet computed for: {}", LOG_TAG, block_num),
            Some(proof) => {
                log::info!("{} found proof: {:#?} for {}", LOG_TAG, proof, block_num);

                // choose the aggregation proof if not empty
                let (is_aggregated, proof_result) = {
                    if proof.aggregation.proof.len() != 0 {
                        (true, proof.aggregation)
                    } else {
                        (false, proof.circuit)
                    }
                };

                let mut verifier_calldata = vec![];
                let mut tmp_buf = vec![0u8; 32];

                proof_result.instance.iter().for_each(|v| {
                    v.to_big_endian(&mut tmp_buf);
                    verifier_calldata.extend_from_slice(&tmp_buf);
                });
                verifier_calldata.extend_from_slice(proof_result.proof.as_ref());

                let mut proof_data = vec![];
                proof_data.extend_from_slice(block.hash.unwrap().as_ref());

                // this is temporary until proper contract setup
                let verifier_addr = U256::from(proof_result.label.as_bytes());
                verifier_addr.to_big_endian(&mut tmp_buf);
                proof_data.extend_from_slice(&tmp_buf);

                let is_aggregated = match is_aggregated {
                    true => U256::one(),
                    false => U256::zero(),
                };
                is_aggregated.to_big_endian(&mut tmp_buf);
                proof_data.extend_from_slice(&tmp_buf);

                proof_data.extend_from_slice(&verifier_calldata);

                let proof_data = Bytes::from(proof_data);
                log::debug!("proof_data: {}", proof_data);
                let calldata = self
                    .ro
                    .bridge_abi
                    .function("finalizeBlock")
                    .unwrap()
                    .encode_input(&[proof_data.into_token()])
                    .expect("calldata");

                let l1_bridge_addr = Some(self.config.lock().await.l1_bridge);
                self.transaction_to_l1(l1_bridge_addr, U256::zero(), calldata)
                    .await
                    .expect("receipt");
            }
        }

        Ok(())
    }

    pub async fn transaction_to_l1(
        &self,
        to: Option<Address>,
        value: U256,
        calldata: Vec<u8>,
    ) -> Result<TransactionReceipt, String> {
        send_transaction_to_l1(
            &self.ro.http_client,
            &self.config.lock().await.l1_rpc_url,
            &self.ro.l1_wallet,
            to,
            value,
            calldata,
        )
        .await
    }

    pub async fn transaction_to_l2(
        &self,
        to: Option<Address>,
        value: U256,
        calldata: Vec<u8>,
        gas_limit: Option<U256>,
    ) -> Result<H256, String> {
        send_transaction_to_l2(
            &self.ro.http_client,
            &self.config.lock().await.l2_rpc_url,
            &self.ro.l2_wallet,
            to,
            value,
            calldata,
            gas_limit,
        )
        .await
    }

    /// Estimates gas against "latest" block and returns a raw signed transaction.
    /// Throws on error.
    pub async fn sign_l2(
        &self,
        to: Option<Address>,
        value: U256,
        nonce: U256,
        calldata: Vec<u8>,
    ) -> Bytes {
        self.sign_l2_given_block_tag(to, value, nonce, calldata, None)
            .await
            .expect("sign_l2")
    }

    /// Estimates gas against `option_block` or "latest" block and returns a raw signed
    /// transaction.
    pub async fn sign_l2_given_block_tag(
        &self,
        to: Option<Address>,
        value: U256,
        nonce: U256,
        calldata: Vec<u8>,
        option_block: Option<String>,
    ) -> Result<Bytes, String> {
        let wallet = &self.ro.l2_wallet;
        let wallet_addr: Address = wallet.address();
        let gas_price: U256 = self.request_l2("eth_gasPrice", ()).await?;
        let mut tx = TransactionRequest::new()
            .chain_id(wallet.chain_id())
            .from(wallet_addr)
            .nonce(nonce)
            .value(value)
            .gas_price(gas_price * 2u64)
            .data(calldata);
        if let Some(to) = to {
            tx = tx.to(to);
        };
        let block_tag = option_block.unwrap_or_else(|| "latest".into());
        let estimate: U256 = self.request_l2("eth_estimateGas", (&tx, block_tag)).await?;
        let tx = tx.gas(estimate).into();
        let sig = wallet
            .sign_transaction(&tx)
            .await
            .map_err(|e| e.to_string())?;

        Ok(tx.rlp_signed(&sig))
    }

    pub async fn request_l1<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        args: T,
    ) -> Result<R, String> {
        jsonrpc_request_client(
            RPC_REQUEST_TIMEOUT,
            &self.ro.http_client,
            &self.config.lock().await.l1_rpc_url,
            method,
            args,
        )
        .await
    }

    pub async fn request_l2<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        args: T,
    ) -> Result<R, String> {
        jsonrpc_request_client(
            RPC_REQUEST_TIMEOUT,
            &self.ro.http_client,
            &self.config.lock().await.l2_rpc_url,
            method,
            args,
        )
        .await
    }

    /// Returns a timestamp that takes care of being greater than the previous one.
    /// This can potentially lead to a timestamp too far into the future
    /// if used too fast.
    async fn next_timestamp(&self) -> u64 {
        let mut ts = timestamp();
        let mut rw = self.rw.lock().await;

        if ts <= rw._prev_timestamp {
            ts = rw._prev_timestamp + 1;
        }
        rw._prev_timestamp = ts;

        ts
    }

    /// Creates a new block with `transactions` on `l2_node`.
    /// If `transactions` is `Some` then any transaction errors
    /// are returned as `Err`. Otherwise it draws from the transaction pool and reverted
    /// transactions are not considered to be errors.
    async fn prepare_block(
        &self,
        timestamp: u64,
        transactions: Option<&Vec<Bytes>>,
    ) -> Result<Block<Transaction>, String> {
        // request new block
        let prepared_block: Block<Transaction> = self
            .request_l2(
                "miner_sealBlock",
                [SealBlockRequest {
                    parent: &self.rw.lock().await.chain_state.head_block_hash,
                    random: &H256::zero(),
                    timestamp: &timestamp.into(),
                    transactions,
                }],
            )
            .await?;
        log::info!(
            "submitted block assembly request to l2 node - txs: {}",
            prepared_block.transactions.len()
        );

        Ok(prepared_block)
    }

    /// Set canonical chain head on `l2_node` and update `chain_state`.
    pub async fn set_chain_head(&self, block_hash: H256) -> Result<(), String> {
        let res: bool = self.request_l2("miner_setHead", [block_hash]).await?;

        if !res {
            return Err(format!("unable to set chain head to {block_hash:?}"));
        }

        self.rw.lock().await.chain_state.head_block_hash = block_hash;
        Ok(())
    }

    /// Mines a new block on `l2_node` and sets the chain head.
    /// The transaction pool will be used if `transactions` is `None`.
    pub async fn mine_block(
        &self,
        transactions: Option<&Vec<Bytes>>,
    ) -> Result<Block<Transaction>, String> {
        let block = self
            .prepare_block(self.next_timestamp().await, transactions)
            .await?;

        self.set_chain_head(block.hash.unwrap()).await?;
        Ok(block)
    }

    /// keeps track of l2 bridge message events
    async fn sync_l2(&self) {
        // TODO: DRY syncing mechanics w/ l1
        let latest_block: U64 = self
            .request_l2("eth_blockNumber", ())
            .await
            .expect("eth_blockNumber");
        let mut last_to_block: U64 = U64::zero();
        let mut from: U64 = self.rw.lock().await.l2_last_sync_block + 1;
        let mut filter = Filter::new()
            .address(ValueOrArray::Value(self.ro.l2_message_deliverer_addr))
            .topic0(ValueOrArray::Value(self.ro.message_delivered_topic));
        let mut executed_msgs = vec![];

        while from <= latest_block {
            // TODO: increase or decrease request range depending on fetch success
            let to = cmp::min(from + 1u64, latest_block);
            log::trace!("fetching logs from={} to={}", from, to);
            filter = filter.from_block(from).to_block(to);

            let logs: Vec<Log> = self
                .request_l2("eth_getLogs", [&filter])
                .await
                .expect("eth_getLogs");
            // TODO: ugly hack to fix geth inconstency issues
            if !logs.is_empty() {
                last_to_block = to;
            }

            for log in logs {
                let message_id = H256::from_slice(log.data.as_ref());
                executed_msgs.push(message_id);
            }

            from = to + 1u64;
        }

        if last_to_block != U64::zero() {
            let mut rw = self.rw.lock().await;
            rw.l2_last_sync_block = last_to_block;
            rw.l2_delivered_messages.extend_from_slice(&executed_msgs);
        }
    }

    /// keeps track of L2 > L1 message events
    async fn record_l2_messages(&self, block_hash: H256) {
        let filter = Filter::new()
            .address(ValueOrArray::Value(self.ro.l2_message_dispatcher_addr))
            .topic0(ValueOrArray::Value(self.ro.message_dispatched_topic))
            .at_block_hash(block_hash);
        let logs: Vec<Log> = self
            .request_l2("eth_getLogs", [&filter])
            .await
            .expect("eth_getLogs");

        log::trace!("L2: {} relay events for {}", logs.len(), block_hash);
        let mut pending = vec![];
        for log in logs {
            let beacon = self._parse_message_beacon(log);
            log::info!("L1Relay: {:?}", beacon.id);
            log::debug!("{:?}", beacon);
            pending.push(beacon);
        }

        let mut rw = self.rw.lock().await;
        rw.l2_message_queue.extend(pending);
    }

    pub async fn relay_to_l1(&self) {
        let mut rw = self.rw.lock().await;
        let len = rw.l2_message_queue.len();

        if len == 0 {
            return;
        }

        // TODO: we are going to lose messages if we panic below
        let todo: Vec<MessageBeacon> = rw.l2_message_queue.drain(0..cmp::min(32, len)).collect();
        drop(rw);

        const LOG_TAG: &str = "L1:deliverMessageWithProof:";
        let l1_bridge_addr = Some(self.config.lock().await.l1_bridge);
        for msg in todo {
            {
                // check deadline
                let ts_with_padding = U256::from(timestamp() + 900);
                if msg.deadline < ts_with_padding {
                    log::info!("{} {:?} deadline exceeded", LOG_TAG, msg.id);
                    log::debug!("{:?}", msg);
                    continue;
                }
            }

            let found = self
                .rw
                .lock()
                .await
                .l1_delivered_messages
                .iter()
                .any(|&e| e == msg.id);

            log::trace!("{} skip={} {:?}", LOG_TAG, found, msg.id);
            log::debug!("{:?}", msg);
            if found {
                continue;
            }

            // latest finalized block hash
            let block_hash = self.rw.lock().await.chain_state.finalized_block_hash;
            // calculate the storage slot for this message
            let storage_slot = msg.storage_slot();
            // request proof
            let proof_obj: ProofRequest = self
                .request_l2(
                    "eth_getProof",
                    (
                        self.ro.l2_message_dispatcher_addr,
                        [storage_slot],
                        block_hash,
                    ),
                )
                .await
                .expect("eth_getProof");
            let l2_block_header: BlockHeader = self
                .request_l2("eth_getHeaderByHash", [block_hash])
                .await
                .expect("eth_getHeaderByHash");
            let mut tmp = vec![0u8; 32];
            let mut bytes = self
                .ro
                .bridge_abi
                .function("multicall")
                .unwrap()
                .encode_input(&[])
                .unwrap();
            let storage_root = keccak256(proof_obj.storage_proof[0].proof[0].as_ref());
            let origin_timestamp = self
                .call_fn_l1("getTimestampForStorageRoot", &[storage_root.into_token()])
                .await
                .expect("getTimestampForStorageRoot");

            // block data
            if origin_timestamp.is_zero() {
                let block_data: Bytes = self
                    .request_l2("debug_getHeaderRlp", [l2_block_header.number.as_u64()])
                    .await
                    .expect("block_data");
                let account_proof: Bytes =
                    Bytes::from(marshal_proof_single(&proof_obj.account_proof));
                let calldata = self
                    .ro
                    .bridge_abi
                    .function("importForeignBridgeState")
                    .unwrap()
                    .encode_input(&[block_data.into_token(), account_proof.into_token()])
                    .expect("importForeignBridgeState");
                U256::from(calldata.len()).to_big_endian(&mut tmp);
                bytes.extend(&tmp[28..32]);
                bytes.extend(calldata);
            }

            // relay message
            {
                let proof: Bytes =
                    Bytes::from(marshal_proof_single(&proof_obj.storage_proof[0].proof));
                let calldata = self
                    .ro
                    .bridge_abi
                    .function("deliverMessageWithProof")
                    .unwrap()
                    .encode_input(&[
                        msg.from.into_token(),
                        msg.to.into_token(),
                        msg.value.into_token(),
                        msg.fee.into_token(),
                        msg.deadline.into_token(),
                        msg.nonce.into_token(),
                        Token::Bytes(msg.calldata),
                        proof.into_token(),
                    ])
                    .expect("calldata");
                U256::from(calldata.len()).to_big_endian(&mut tmp);
                bytes.extend(&tmp[28..32]);
                bytes.extend(calldata);
            }

            // TODO: support relaying multiple messages at once
            self.transaction_to_l1(l1_bridge_addr, U256::zero(), bytes)
                .await
                .expect("receipt");
        }
    }

    fn _parse_message_beacon(&self, log: Log) -> MessageBeacon {
        // TODO: this is really ugly. consider finding a alternative
        let evt = self.ro.bridge_abi.event("MessageDispatched").unwrap();
        let evt = evt
            .parse_log(RawLog::from((log.topics, log.data.to_vec())))
            .unwrap();

        let id: H256 = keccak256(log.data).into();
        let from = evt.params[0].value.to_owned().into_address().unwrap();
        let to = evt.params[1].value.to_owned().into_address().unwrap();
        let value = evt.params[2].value.to_owned().into_uint().unwrap();
        let fee = evt.params[3].value.to_owned().into_uint().unwrap();
        let deadline = evt.params[4].value.to_owned().into_uint().unwrap();
        let nonce = evt.params[5].value.to_owned().into_uint().unwrap();
        let calldata = evt.params[6].value.to_owned().into_bytes().unwrap();

        MessageBeacon {
            id,
            from,
            to,
            value,
            fee,
            deadline,
            nonce,
            calldata,
        }
    }

    async fn call_fn_l1(
        &self,
        function_name: &str,
        function_args: &[Token],
    ) -> Result<H256, String> {
        let calldata = Bytes::from(
            self.ro
                .bridge_abi
                .function(function_name)
                .unwrap()
                .encode_input(function_args)
                .expect("calldata"),
        );
        let l1_bridge_addr = self.config.lock().await.l1_bridge;
        let resp: Result<H256, String> = self
            .request_l1(
                "eth_call",
                serde_json::json!([{ "to": l1_bridge_addr, "data": calldata }, "latest"]),
            )
            .await;

        resp
    }

    /// TODO: WIP - moved from prover/inputs
    /// Generates a witness suitable for the L1 Verifier contract(s) for block `block_num`.
    pub async fn request_witness(&self, block_num: &U64) -> Result<Witness, String> {
        let block: Block<Transaction> = self
            .request_l2("eth_getBlockByNumber", (block_num, true))
            .await
            .expect("block");
        let mut history_hashes = vec![H256::zero(); 256];
        let mut block_hash = block.parent_hash;
        history_hashes[255] = block_hash;
        for i in 0..255 {
            if block_hash != H256::zero() {
                let header: BlockHeader =
                    self.request_l2("eth_getHeaderByHash", [block_hash]).await?;
                block_hash = header.parent_hash;
            }
            history_hashes[254 - i] = block_hash;
        }
        let chain_id = self.ro.l2_wallet.chain_id();
        let witness: Vec<u8> = encode_verifier_witness(&block, &history_hashes, &chain_id)?;
        let witness = Witness {
            randomness: U256::zero(),
            input: Bytes::from(witness),
        };

        Ok(witness)
    }

    pub async fn request_proof(&self, block_num: &U64) -> Result<Option<Proofs>, String> {
        if self.config.lock().await.dummy_prover {
            log::warn!("COORDINATOR_DUMMY_PROVER");
            let instance: Vec<U256> = {
                let block_data = self
                    .request_witness(block_num)
                    .await
                    .expect("witness")
                    .input;
                let func = self.ro.bridge_abi.function("buildCommitment").unwrap();
                let calldata = Bytes::from(
                    func.encode_input(&[block_data.into_token()])
                        .expect("calldata"),
                );
                let l1_bridge_addr = self.config.lock().await.l1_bridge;
                let result: Bytes = self
                    .request_l1(
                        "eth_call",
                        serde_json::json!([{ "to": l1_bridge_addr, "data": calldata }, "latest"]),
                    )
                    .await
                    .expect("eth_call buildCommitment");
                let result: Vec<Token> = func
                    .decode_output(&result)
                    .expect("decode_output")
                    .get(0)
                    .unwrap()
                    .to_owned()
                    .into_array()
                    .expect("into_array");
                let result: Vec<U256> = result
                    .iter()
                    .map(|item| item.to_owned().into_uint().expect("into_uint"))
                    .collect();

                result
            };
            let mut proofs = Proofs::default();
            proofs.circuit.proof = vec![0u8; 256].into();
            proofs.circuit.instance = instance;
            proofs.circuit.label = "DUMMY_VERIFIER".into();

            return Ok(Some(proofs));
        }

        let config = self.config.lock().await;
        let prover_rpcd_url = config.prover_rpcd_url.clone();
        let proof_options = ProofRequestOptions {
            circuit: config.circuit_name.clone(),
            block: block_num.as_u64(),
            rpc: config.l2_rpc_url.to_string(),
            retry: false,
            param: config.params_path.clone(),
            mock: config.mock_prover,
            aggregate: config.aggregate_proof,
            mock_feedback: config.mock_prover_if_error,
            verify_proof: config.verify_proof,
        };
        drop(config);

        let resp = jsonrpc_request_client(
            RPC_REQUEST_TIMEOUT,
            &self.ro.http_client,
            &prover_rpcd_url,
            "proof",
            [proof_options],
        )
        .await;

        match resp {
            Err(err) => {
                match err.as_ref() {
                    "no result in response" => {
                        // ...not an error
                        Ok(None)
                    }
                    _ => Err(err),
                }
            }
            Ok(val) => Ok(Some(val)),
        }
    }

    /// Returns the current coordinator configuration.
    pub async fn get_config(&self) -> Config {
        self.config.lock().await.to_owned()
    }

    /// Sets the coordinator configuration.
    /// Not all changes to the config may be reflected.
    pub async fn set_config(&self, config: Config) {
        // TODO: doesn't update all config values at the moment.
        *self.config.lock().await = config;
    }
}

fn get_abi() -> Abi {
    AbiParser::default()
        .parse(&[
            "event BlockSubmitted()",
            "event BlockFinalized(bytes32 blockHash)",
            "event MessageDispatched(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data)",
            "event MessageDelivered(bytes32 id)",
            "function submitBlock(bytes)",
            "function finalizeBlock(bytes proof)",
            "function deliverMessageWithProof(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data, bytes proof)",
            "function stateRoots(bytes32 blockHash) returns (bytes32)",
            "function importForeignBlock(uint256 blockNumber, bytes32 blockHash)",
            "function initGenesis(bytes32 blockHash, bytes32 stateRoot)",
            "function buildCommitment(bytes) returns (uint256[])",
            "function importForeignBridgeState(bytes, bytes)",
            "function multicall()",
            "function getTimestampForStorageRoot(bytes32 storageRoot) returns (uint256)",
        ])
        .expect("parse abi")
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

async fn get_wallet(rcp_url: &Uri, sign_key: &str) -> LocalWallet {
    let chain_id: U64 = jsonrpc_request(rcp_url, "eth_chainId", ())
        .await
        .expect("chain id L1");

    sign_key
        .parse::<LocalWallet>()
        .expect("cannot create LocalWallet from private key")
        .with_chain_id(chain_id.as_u64())
}
