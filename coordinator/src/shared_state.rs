use std::cmp;
use std::collections::HashMap;
use std::env::var;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::Mutex;

use ethers_core::abi::Abi;
use ethers_core::abi::AbiParser;
use ethers_core::abi::RawLog;
use ethers_core::abi::Token;
use ethers_core::abi::Tokenizable;
use ethers_core::types::{
    Address, Block, Bytes, Filter, Log, Transaction, TransactionRequest, TxpoolStatus,
    ValueOrArray, H256, U256, U64,
};
use ethers_core::utils::keccak256;
use ethers_signers::LocalWallet;
use ethers_signers::Signer;

use hyper::client::HttpConnector;
use hyper::Uri;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::structs::*;
use crate::utils::*;

pub struct RoState {
    pub l2_node: Uri,
    pub l1_node: Uri,
    pub prover_node: Uri,

    pub l1_bridge_addr: Address,
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

pub struct RwState {
    pub chain_state: ForkchoiceStateV1,
    pub nodes: Vec<Uri>,
    pub prover_requests: HashMap<U64, Option<Proofs>>,
    pub pending_proofs: u32,
    pub l1_last_sync_block: U64,
    pub l2_last_sync_block: U64,
    pub l1_message_queue: Vec<MessageBeacon>,
    pub l2_delivered_messages: Vec<H256>,
    pub l2_message_queue: Vec<MessageBeacon>,
    pub l1_delivered_messages: Vec<H256>,

    /// keeps track of the timestamp used for preparing the last block
    _prev_timestamp: u64,
}

#[derive(Clone)]
pub struct SharedState {
    pub ro: Arc<RoState>,
    pub rw: Arc<Mutex<RwState>>,
}

impl SharedState {
    pub fn new(
        l2_url: Uri,
        l1_url: Uri,
        l1_bridge: Address,
        l1_wallet: LocalWallet,
        l2_wallet: LocalWallet,
        prover_node: Uri,
    ) -> SharedState {
        let abi = AbiParser::default()
            .parse(&[
                "event BlockSubmitted()",
                "event BlockFinalized(bytes32 blockHash)",
                "event MessageDispatched(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data)",
                "event MessageDelivered(bytes32 id)",
                "function submitBlock(bytes)",
                "function finalizeBlock(bytes32 blockHash, bytes witness, bytes proof)",
                "function deliverMessageWithProof(address from, address to, uint256 value, uint256 fee, uint256 deadline, uint256 nonce, bytes data, bytes proof)",
                "function stateRoot() returns (bytes32)",
                "function importBlockHeader(uint256 blockNumber, bytes32 blockHash, bytes blockHeader)",
            ])
            .expect("parse abi");

        let beacon_topic = abi.event("BlockSubmitted").unwrap().signature();
        let block_finalized_topic = abi.event("BlockFinalized").unwrap().signature();
        let message_dispatched_topic = abi.event("MessageDispatched").unwrap().signature();
        let message_delivered_topic = abi.event("MessageDelivered").unwrap().signature();

        Self {
            ro: Arc::new(RoState {
                l2_node: l2_url,
                l1_node: l1_url,
                prover_node,

                l1_bridge_addr: l1_bridge,
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
            }),
            rw: Arc::new(Mutex::new(RwState {
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
                l1_message_queue: Vec::new(),
                l2_delivered_messages: Vec::new(),
                l2_message_queue: Vec::new(),
                l1_delivered_messages: Vec::new(),

                _prev_timestamp: 0,
            })),
        }
    }

    pub async fn from_env() -> SharedState {
        let l2_url = var("L2_RPC_URL")
            .expect("L2_RPC_URL env var")
            .parse::<Uri>()
            .expect("Uri from L2_RPC_URL");
        let l1_url = var("L1_RPC_URL")
            .expect("L1_RPC_URL env var")
            .parse::<Uri>()
            .expect("Uri from L1_RPC_URL");
        let l1_bridge = var("L1_BRIDGE")
            .expect("L1_BRIDGE env var")
            .parse::<Address>()
            .expect("Address from L1_BRIDGE");

        let chain_id: U64 = jsonrpc_request(&l1_url, "eth_chainId", ())
            .await
            .expect("chain id");
        let l1_wallet = var("L1_PRIV")
            .expect("L1_PRIV env var")
            .parse::<LocalWallet>()
            .expect("LocalWallet from L1_PRIV")
            .with_chain_id(chain_id.as_u64());

        let chain_id: U64 = jsonrpc_request(&l2_url, "eth_chainId", ())
            .await
            .expect("chain id");
        // TODO: support different keys
        let l2_wallet = var("L1_PRIV")
            .expect("L1_PRIV env var")
            .parse::<LocalWallet>()
            .expect("LocalWallet from L1_PRIV")
            .with_chain_id(chain_id.as_u64());

        let prover_node = var("PROVER_RPCD_URL")
            .expect("PROVER_RPCD_URL env var")
            .parse::<Uri>()
            .expect("Uri from PROVER_RPCD_URL");

        Self::new(l2_url, l1_url, l1_bridge, l1_wallet, l2_wallet, prover_node)
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
    }

    pub async fn sync(&self) {
        // sync events
        let latest_block: U64 = self
            .request_l1("eth_blockNumber", ())
            .await
            .expect("eth_blockNumber");
        let mut from: U64 = self.rw.lock().await.l1_last_sync_block + 1;
        let mut filter = Filter::new()
            .address(ValueOrArray::Value(self.ro.l1_bridge_addr))
            .topic0(ValueOrArray::Array(vec![
                self.ro.block_beacon_topic,
                self.ro.block_finalized_topic,
                self.ro.message_dispatched_topic,
                self.ro.message_delivered_topic,
            ]));

        while from <= latest_block {
            // TODO: increase or decrease request range depending on fetch success
            let to = cmp::min(from + 1u64, latest_block);
            log::info!("fetching l1 logs from={} to={}", from, to);
            filter = filter.from_block(from).to_block(to);

            let logs: Vec<Log> = self
                .request_l1("eth_getLogs", [&filter])
                .await
                .expect("eth_getLogs");

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
                    let block_hash = H256::from(keccak256(&tx_data[start..end]));
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
                    self.rw.lock().await.l1_message_queue.push(beacon);
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

        self.rw.lock().await.l1_last_sync_block = latest_block;
        self.sync_l2().await;
    }

    pub async fn mine(&self) {
        // TODO: verify that head_hash is correct
        let head_hash = get_chain_head_hash(&self.ro.http_client, &self.ro.l2_node).await;
        self.rw.lock().await.chain_state.head_block_hash = head_hash;

        {
            // always send a miner_init request to enable transaction pool etc.
            // just to account for the case that the node was restarted
            let _: Option<Address> = self.request_l2("miner_init", ()).await.unwrap_or_default();
        }

        {
            // check l1 > l2 message queue
            // TODO: state mgmt for messages, processing should be done in a different step
            // and always go through the l2 bridge
            let mut rw = self.rw.lock().await;
            let len = rw.l1_message_queue.len();

            if len > 0 {
                let mut messages = vec![];
                // TODO: we are going to lose messages if we panic below
                let todo: Vec<MessageBeacon> =
                    rw.l1_message_queue.drain(0..cmp::min(32, len)).collect();
                drop(rw);

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
                // import l1 block
                let calldata = self
                    .ro
                    .bridge_abi
                    .function("importBlockHeader")
                    .unwrap()
                    .encode_input(&[
                        U256::from(l1_block_header.number.as_u64()).into_token(),
                        l1_block_header.hash.into_token(),
                        block_data.into_token(),
                    ])
                    .expect("calldata");
                let block_import_tx = self
                    .sign_l2(
                        self.ro.l2_message_deliverer_addr,
                        U256::zero(),
                        nonce,
                        calldata,
                    )
                    .await;
                messages.push(block_import_tx.clone());
                nonce = nonce + 1;
                // Use this block to run the messages against.
                // This is required for proper gas calculation.
                let temporary_block = self._prepare_block(Some(vec![block_import_tx])).await;

                let ts = U256::from(timestamp());
                for msg in todo {
                    if msg.deadline < ts {
                        log::info!("{} {:?} deadline exceeded", LOG_TAG, msg.id);
                        log::debug!("{:?}", msg);
                        continue;
                    }

                    let found = self
                        .rw
                        .lock()
                        .await
                        .l2_delivered_messages
                        .iter()
                        .any(|&e| e == msg.id);

                    log::info!("{} skip={} {:?}", LOG_TAG, found, msg.id);
                    log::debug!("{:?}", msg);
                    if !found {
                        // calculate the storage slot for this message
                        let storage_slot = msg.storage_slot();
                        // request proof
                        let proof_obj: ProofRequest = self
                            .request_l1(
                                "eth_getProof",
                                (self.ro.l1_bridge_addr, [storage_slot], l1_block_header.hash),
                            )
                            .await
                            .expect("eth_getProof");
                        // encode proof
                        let proof: Bytes = Bytes::from(marshal_proof(
                            &proof_obj.account_proof,
                            &proof_obj.storage_proof[0].proof,
                        ));
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
                        messages.push(
                            self.sign_l2_given_block_tag(
                                self.ro.l2_message_deliverer_addr,
                                U256::zero(),
                                nonce,
                                calldata,
                                Some(format!("{:#066x}", temporary_block.hash.unwrap())),
                            )
                            .await,
                        );
                        nonce = nonce + 1;
                    }
                }

                if !messages.is_empty() {
                    self.mine_block(Some(messages)).await;
                }
            }
        }

        // check if we can mine a block
        let resp: TxpoolStatus = self.request_l2("txpool_status", ()).await.unwrap();
        let pending_txs = resp.pending.as_u64();

        if pending_txs != 0 {
            self.mine_block(None).await;
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
                &self.ro.l2_node,
                &safe_hash,
                &head_hash,
            )
            .await;

            log::info!("blocks to be submitted: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                log::info!("submit_block: {}", format_block(block));
                {
                    let block_data: Bytes = self
                        .request_l2("debug_getHeaderRlp", [block.number.unwrap().as_u64()])
                        .await
                        .expect("block");

                    let calldata = self
                        .ro
                        .bridge_abi
                        .function("submitBlock")
                        .unwrap()
                        .encode_input(&[block_data.into_token()])
                        .expect("calldata");

                    self.transaction_to_l1(self.ro.l1_bridge_addr, U256::zero(), calldata)
                        .await;
                }
            }
        }
    }

    pub async fn finalize_blocks(&self) {
        // block finalization
        let safe_hash = self.rw.lock().await.chain_state.safe_block_hash;
        let final_hash = self.rw.lock().await.chain_state.finalized_block_hash;
        if final_hash != safe_hash {
            let blocks = get_blocks_between(
                &self.ro.http_client,
                &self.ro.l2_node,
                &final_hash,
                &safe_hash,
            )
            .await;

            log::info!("blocks for finalization: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                self.finalize_block(block).await;
            }
        }
    }

    pub async fn finalize_block(&self, block: &Block<H256>) {
        const LOG_TAG: &str = "L1:finalize_block:";
        log::debug!("{} {}", LOG_TAG, format_block(block));

        let block_num = block.number.unwrap();
        let proofs: Result<Option<Proofs>, String> = self.request_proof(&block_num).await;

        if let Err(err) = proofs {
            log::error!("{}:{} {:?}", LOG_TAG, block_num, err);
            return;
        }

        match proofs.unwrap() {
            None => log::info!("{} proof not yet computed for: {}", LOG_TAG, block_num),
            Some(proof) => {
                log::info!("{} found proof: {:?} for {}", LOG_TAG, proof, block_num);

                let block_hash = block.hash.unwrap();
                let witness: Bytes = self
                    .request_l2("debug_getHeaderRlp", [block.number.unwrap().as_u64()])
                    .await
                    .expect("debug_getHeaderRlp");
                let mut proof_data = vec![];
                proof_data.extend_from_slice(proof.evm_proof.as_ref());
                proof_data.extend_from_slice(proof.state_proof.as_ref());
                let proof_data = Bytes::from(proof_data);

                let calldata = self
                    .ro
                    .bridge_abi
                    .function("finalizeBlock")
                    .unwrap()
                    .encode_input(&[
                        block_hash.into_token(),
                        witness.into_token(),
                        proof_data.into_token(),
                    ])
                    .expect("calldata");

                self.transaction_to_l1(self.ro.l1_bridge_addr, U256::zero(), calldata)
                    .await;
            }
        }
    }

    pub async fn transaction_to_l1(&self, to: Address, value: U256, calldata: Vec<u8>) {
        send_transaction_to_l1(
            &self.ro.http_client,
            &self.ro.l1_node,
            &self.ro.l1_wallet,
            to,
            value,
            calldata,
        )
        .await;
    }

    pub async fn transaction_to_l2(
        &self,
        to: Address,
        value: U256,
        calldata: Vec<u8>,
    ) -> Result<H256, String> {
        send_transaction_to_l2(
            &self.ro.http_client,
            &self.ro.l2_node,
            &self.ro.l2_wallet,
            to,
            value,
            calldata,
        )
        .await
    }

    /// Estimates gas against "latest" block and returns a raw signed transaction.
    /// Throws on error.
    pub async fn sign_l2(&self, to: Address, value: U256, nonce: U256, calldata: Vec<u8>) -> Bytes {
        self.sign_l2_given_block_tag(to, value, nonce, calldata, None)
            .await
    }

    /// Estimates gas against `option_block` or "latest" block and returns a raw signed
    /// transaction.
    /// Throws on error.
    pub async fn sign_l2_given_block_tag(
        &self,
        to: Address,
        value: U256,
        nonce: U256,
        calldata: Vec<u8>,
        option_block: Option<String>,
    ) -> Bytes {
        let wallet = &self.ro.l2_wallet;
        let wallet_addr: Address = wallet.address();
        let gas_price: U256 = self.request_l2("eth_gasPrice", ()).await.expect("gasPrice");
        let tx = TransactionRequest::new()
            .from(wallet_addr)
            .to(to)
            .nonce(nonce)
            .value(value)
            .gas_price(gas_price * 2u64)
            .data(calldata);
        let block_tag = option_block.unwrap_or_else(|| "latest".into());
        let estimate: U256 = self
            .request_l2("eth_estimateGas", (&tx, block_tag))
            .await
            .expect("estimateGas");
        let tx = tx.gas(estimate).into();
        let sig = wallet.sign_transaction(&tx).await.unwrap();

        tx.rlp_signed(wallet.chain_id(), &sig)
    }

    pub async fn request_l1<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        args: T,
    ) -> Result<R, String> {
        crate::timeout!(
            5000,
            jsonrpc_request_client(&self.ro.http_client, &self.ro.l1_node, method, args).await
        )
    }

    pub async fn request_l2<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        args: T,
    ) -> Result<R, String> {
        crate::timeout!(
            5000,
            jsonrpc_request_client(&self.ro.http_client, &self.ro.l2_node, method, args).await
        )
    }

    async fn _prepare_block(&self, transactions: Option<Vec<Bytes>>) -> Block<Transaction> {
        let mut ts = timestamp();
        let prev_timestamp = self.rw.lock().await._prev_timestamp;
        if prev_timestamp >= ts {
            // This can potentially lead to a timestamp too far into the future
            // if mining too fast.
            ts = prev_timestamp + 1;
        }
        let parent = self.rw.lock().await.chain_state.head_block_hash;
        let random = H256::zero();
        let timestamp: U64 = ts.into();

        // request new block
        let prepared_block: Block<Transaction> = self
            .request_l2(
                "miner_sealBlock",
                [SealBlockRequest {
                    parent,
                    random,
                    timestamp,
                    transactions,
                }],
            )
            .await
            .expect("miner_mineTransaction");
        log::info!(
            "submitted block assembly request to l2 node - txs: {}",
            prepared_block.transactions.len()
        );

        self.rw.lock().await._prev_timestamp = ts;

        prepared_block
    }

    pub async fn mine_block(&self, transactions: Option<Vec<Bytes>>) -> Block<Transaction> {
        let prepared_block = self._prepare_block(transactions).await;
        let block_hash = prepared_block.hash.unwrap();

        // set canonical chain head
        // always returns true or throws
        let _: bool = self
            .request_l2("miner_setHead", [block_hash])
            .await
            .expect("miner_setHead");
        self.rw.lock().await.chain_state.head_block_hash = block_hash;

        prepared_block
    }

    /// keeps track of l2 bridge message events
    async fn sync_l2(&self) {
        // TODO: DRY syncing mechanics w/ l1
        let latest_block: U64 = self
            .request_l2("eth_blockNumber", ())
            .await
            .expect("eth_blockNumber");
        let mut from: U64 = self.rw.lock().await.l2_last_sync_block + 1;
        let mut filter = Filter::new()
            .address(ValueOrArray::Value(self.ro.l2_message_deliverer_addr))
            .topic0(ValueOrArray::Value(self.ro.message_delivered_topic));
        let mut executed_msgs = vec![];

        while from <= latest_block {
            // TODO: increase or decrease request range depending on fetch success
            let to = cmp::min(from + 1u64, latest_block);
            log::info!("fetching logs from={} to={}", from, to);
            filter = filter.from_block(from).to_block(to);

            let logs: Vec<Log> = self
                .request_l2("eth_getLogs", [&filter])
                .await
                .expect("eth_getLogs");

            for log in logs {
                let message_id = H256::from_slice(log.data.as_ref());
                executed_msgs.push(message_id);
            }

            from = to + 1u64;
        }

        let mut rw = self.rw.lock().await;
        rw.l2_last_sync_block = latest_block;
        rw.l2_delivered_messages.extend_from_slice(&executed_msgs);
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

        log::info!("L2: {} relay events for {}", logs.len(), block_hash);
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

            log::info!("{} skip={} {:?}", LOG_TAG, found, msg.id);
            log::debug!("{:?}", msg);
            if found {
                continue;
            }

            // latest state root known on L1
            let state_root = self.state_root_l1().await.expect("l1.stateRoot");
            log::info!("L1:stateRoot: {:?}", state_root);

            // latest finalized block hash, should include `state_root`
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

            // encode proof and send it
            let proof: Bytes = Bytes::from(marshal_proof(
                &proof_obj.account_proof,
                &proof_obj.storage_proof[0].proof,
            ));
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
            self.transaction_to_l1(self.ro.l1_bridge_addr, U256::zero(), calldata)
                .await;
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

    async fn state_root_l1(&self) -> Result<H256, String> {
        let calldata = Bytes::from(
            self.ro
                .bridge_abi
                .function("stateRoot")
                .unwrap()
                .encode_input(&[])
                .expect("calldata"),
        );
        let resp: Result<H256, String> = self
            .request_l1(
                "eth_call",
                serde_json::json!(
                [
                {
                    "to": self.ro.l1_bridge_addr,
                    "data": calldata,
                },
                "latest"
                ]
                ),
            )
            .await;

        resp
    }

    pub async fn request_witness(&self, block_num: &U64) -> Result<Witness, String> {
        crate::timeout!(
            5000,
            jsonrpc_request_client(
                &self.ro.http_client,
                &self.ro.prover_node,
                "witness",
                (block_num.as_u64(), self.ro.l2_node.to_string())
            )
            .await
        )
    }

    pub async fn request_proof(&self, block_num: &U64) -> Result<Option<Proofs>, String> {
        if crate::option_enabled!("DUMMY_PROVER", true).is_some() {
            log::warn!("DUMMY_PROVER");
            let proof = Proofs {
                evm_proof: Bytes::from([0xffu8]),
                state_proof: Bytes::from([0xffu8]),
            };
            return Ok(Some(proof));
        }

        let resp = crate::timeout!(
            5000,
            jsonrpc_request_client(
                &self.ro.http_client,
                &self.ro.prover_node,
                "proof",
                (block_num.as_u64(), self.ro.l2_node.to_string(), false)
            )
            .await
        );

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
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}
