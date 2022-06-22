use coordinator::shared_state::SharedState;
use coordinator::structs::*;
use coordinator::utils::jsonrpc_request;
use coordinator::utils::marshal_proof;
use ethers_core::abi::encode;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::H256;
use ethers_core::types::U256;
use ethers_core::types::U64;
use ethers_core::utils::keccak256;
use ethers_signers::Signer;
use std::env::var;
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;
use tokio::sync::OnceCell;

macro_rules! sync {
    ($shared_state:expr) => {
        // sync bridge and process events
        $shared_state.sync().await;
        while $shared_state.rw.lock().await.l1_message_queue.len() > 0 {
            $shared_state.mine().await;
            $shared_state.sync().await;
        }
    };
}

macro_rules! wait_for_tx {
    ($tx_hash:expr, $url:expr) => {
        let mut resp: Option<TransactionReceipt> = None;

        while (resp.is_none()) {
            resp = jsonrpc_request($url, "eth_getTransactionReceipt", [$tx_hash])
                .await
                .expect("eth_getTransactionReceipt");
        }

        if resp.unwrap().status.unwrap() != U64::from(1) {
            panic!("transaction reverted");
        }
    };
}

macro_rules! finalize_chain {
    ($shared_state:expr) => {
        loop {
            let rw = $shared_state.rw.lock().await;
            if rw.chain_state.head_block_hash == rw.chain_state.finalized_block_hash {
                break;
            }
            drop(rw);

            sync!($shared_state);
            $shared_state.submit_blocks().await;
            $shared_state.finalize_blocks().await;
            sync!($shared_state);
            while $shared_state.rw.lock().await.l2_message_queue.len() != 0 {
                $shared_state.relay_to_l1().await;
                sync!($shared_state);
            }
        }
    };
}

fn init_logger() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .is_test(var("VERBOSE").is_err())
        .try_init();
}

static ONCE: OnceCell<Mutex<SharedState>> = OnceCell::const_new();

async fn get_shared_state() -> &'static Mutex<SharedState> {
    ONCE.get_or_init(|| async {
        let shared_state = SharedState::from_env().await;
        shared_state.init().await;

        Mutex::new(shared_state)
    })
    .await
}

fn zkevm_abi() -> ethers_core::abi::Contract {
    AbiParser::default()
        .parse(&[
            // zkevm native bridge
            "function dispatchMessage(address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) external payable",
        ])
        .expect("parse abi")
}

#[tokio::test]
async fn native_deposit() {
    init_logger();

    let abi = zkevm_abi();
    let shared_state = get_shared_state().await.lock().unwrap();
    let mut deposits: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.ro.l2_node,
        "eth_getBalance",
        (receiver, "latest"),
    )
    .await
    .expect("eth_getBalance");

    {
        // create deposits
        for _ in 0..9 {
            let from = shared_state.ro.l1_wallet.address();
            let to = receiver;
            let value = U256::from(1u64);
            let fee = U256::zero();
            let deadline = U256::from(0xffffffffffffffffu64);
            let nonce: U256 = rand::random::<usize>().into();
            let data = Bytes::from([]);

            let calldata = abi
                .function("dispatchMessage")
                .unwrap()
                .encode_input(&[
                    to.into_token(),
                    fee.into_token(),
                    deadline.into_token(),
                    nonce.into_token(),
                    data.clone().into_token(),
                ])
                .expect("calldata");

            let id: H256 = keccak256(encode(&[
                from.into_token(),
                to.into_token(),
                value.into_token(),
                fee.into_token(),
                deadline.into_token(),
                nonce.into_token(),
                data.into_token(),
            ]))
            .into();

            deposits.push(id);
            expected_balance = expected_balance + value;
            shared_state
                .transaction_to_l1(shared_state.ro.l1_bridge_addr, value, calldata)
                .await;
        }
    }

    sync!(shared_state);

    // verify that all deposit are picked up
    {
        for id in deposits {
            let found = shared_state
                .rw
                .lock()
                .await
                .l2_delivered_messages
                .iter()
                .any(|e| e == &id);
            assert_eq!(true, found, "message id should exist");
        }

        let balance: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }
}

#[tokio::test]
async fn native_withdraw() {
    init_logger();

    let abi = zkevm_abi();
    let shared_state = get_shared_state().await.lock().unwrap();
    let mut messages: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.ro.l1_node,
        "eth_getBalance",
        (receiver, "latest"),
    )
    .await
    .expect("eth_getBalance");

    shared_state.sync().await;
    shared_state.mine().await;

    {
        let mut tx_nonce: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getTransactionCount",
            (shared_state.ro.l2_wallet.address(), "latest"),
        )
        .await
        .expect("nonce");
        let mut txs = vec![];
        for _ in 0..9 {
            let from = shared_state.ro.l2_wallet.address();
            let to = receiver;
            let value = U256::from(1u64);
            let fee = U256::zero();
            let deadline = U256::from(0xffffffffffffffffu64);
            let nonce: U256 = rand::random::<usize>().into();
            let data = Bytes::from([]);
            let calldata = abi
                .function("dispatchMessage")
                .unwrap()
                .encode_input(&[
                    to.into_token(),
                    fee.into_token(),
                    deadline.into_token(),
                    nonce.into_token(),
                    data.clone().into_token(),
                ])
                .expect("calldata");

            let id: H256 = keccak256(encode(&[
                from.into_token(),
                to.into_token(),
                value.into_token(),
                fee.into_token(),
                deadline.into_token(),
                nonce.into_token(),
                data.into_token(),
            ]))
            .into();

            messages.push(id);
            expected_balance = expected_balance + value;
            txs.push(
                shared_state
                    .sign_l2(
                        shared_state.ro.l2_message_dispatcher_addr,
                        value,
                        tx_nonce,
                        calldata,
                    )
                    .await,
            );
            tx_nonce = tx_nonce + 1;
        }

        shared_state.mine_block(Some(txs)).await;
    }

    finalize_chain!(shared_state);

    // verify that all messages are picked up
    {
        shared_state.sync().await;
        for id in messages {
            let found = shared_state
                .rw
                .lock()
                .await
                .l1_delivered_messages
                .iter()
                .any(|e| e == &id);
            assert_eq!(true, found, "message id should exist");
        }
    }

    {
        // check final balance on L1
        let balance: U256 = jsonrpc_request(
            &shared_state.ro.l1_node,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }
}

#[tokio::test]
async fn hop_deposit() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            // hop-protocol
            "function sendToL2(uint256 chainId, address recipient, uint256 amount, uint256 amountOutMin, uint256 deadline, address relayer, uint256 relayerFee)",
        ])
        .expect("parse abi");

    let shared_state = get_shared_state().await.lock().unwrap();

    // hop-protocol deposit
    {
        let hop: Address = "0xb8901acB165ed027E32754E0FFe830802919727f"
            .parse()
            .unwrap();
        let chain_id = U256::from(99u64);
        let recipient = Address::zero();
        let amount = U256::from(0x174876e8000u64);
        let amount_out_min = U256::from(0x173c91838du64);
        let deadline = U256::MAX;
        let relayer = Address::zero();
        let relayer_fee = U256::zero();
        let calldata = abi
            .function("sendToL2")
            .unwrap()
            .encode_input(&[
                chain_id.into_token(),
                recipient.into_token(),
                amount.into_token(),
                amount_out_min.into_token(),
                deadline.into_token(),
                relayer.into_token(),
                relayer_fee.into_token(),
            ])
            .expect("calldata");

        let balance_before: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getBalance",
            (recipient, "latest"),
        )
        .await
        .expect("eth_getBalance");

        shared_state.transaction_to_l1(hop, amount, calldata).await;
        sync!(shared_state);

        let balance_after: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getBalance",
            (recipient, "latest"),
        )
        .await
        .expect("eth_getBalance");

        let min_expected_balance = balance_before + amount_out_min;
        assert!(
            balance_after >= min_expected_balance,
            "ETH balance after hop deposit"
        );
    }
}

#[tokio::test]
async fn hop_cross_chain_message() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            // hop-protocol
            "function swapAndSend(uint256 chainId, address recipient, uint256 amount, uint256 bonderFee, uint256 amountOutMin, uint256 deadline, uint256 destinationAmountOutMin, uint256 destinationDeadline)",
            "function commitTransfers(uint256 destinationChainId)",
            "function chainBalance(uint256)",
        ])
        .expect("parse abi");
    let calldata = abi
        .function("chainBalance")
        .unwrap()
        .encode_input(&[U256::from(99u64).into_token()])
        .expect("calldata");
    let get_chain_balance = serde_json::json!(
    {
        "to": "0xb8901acb165ed027e32754e0ffe830802919727f",
        "data": Bytes::from(calldata),
    }
    );

    let chain_id = U256::from(98u64);
    let shared_state = get_shared_state().await.lock().unwrap();

    sync!(shared_state);

    // balance on L1 hop bridge for L2 chain
    let chain_balance_before: U256 = jsonrpc_request(
        &shared_state.ro.l1_node,
        "eth_call",
        (&get_chain_balance, "latest"),
    )
    .await
    .expect("eth_call");

    {
        // withdraw from hop
        let hop: Address = "0x86cA30bEF97fB651b8d866D45503684b90cb3312"
            .parse()
            .unwrap();
        let recipient = Address::zero();
        let amount = U256::from(0x38d7ea4c68000u64);
        let bonder_fee = U256::from(0x54c89e3b2703u64);
        let amount_out_min = U256::from(0x330b7c6533df8u64);
        let deadline = U256::MAX;
        let destination_amount_out_min = amount_out_min - bonder_fee;
        let destination_deadline = U256::MAX;
        let calldata = abi
            .function("swapAndSend")
            .unwrap()
            .encode_input(&[
                chain_id.into_token(),
                recipient.into_token(),
                amount.into_token(),
                bonder_fee.into_token(),
                amount_out_min.into_token(),
                deadline.into_token(),
                destination_amount_out_min.into_token(),
                destination_deadline.into_token(),
            ])
            .expect("calldata");

        let tx_hash = shared_state
            .transaction_to_l2(hop, amount, calldata)
            .await
            .expect("tx_hash");
        shared_state.mine().await;
        wait_for_tx!(tx_hash, &shared_state.ro.l2_node);
    }

    {
        // commit the hop stateroot and initiate L2 > L1 message
        let hop: Address = "0x83f6244bd87662118d96d9a6d44f09dfff14b30e"
            .parse()
            .unwrap();
        let calldata = abi
            .function("commitTransfers")
            .unwrap()
            .encode_input(&[chain_id.into_token()])
            .expect("calldata");
        let tx_hash_commit = shared_state
            .transaction_to_l2(hop, U256::zero(), calldata)
            .await
            .expect("tx_hash_commit");
        shared_state.mine().await;
        wait_for_tx!(tx_hash_commit, &shared_state.ro.l2_node);
    }

    finalize_chain!(shared_state);

    {
        // verify that the L2 > L1 message was executed successfully
        let chain_balance_after: U256 = jsonrpc_request(
            &shared_state.ro.l1_node,
            "eth_call",
            (&get_chain_balance, "latest"),
        )
        .await
        .expect("eth_call");

        assert!(
            chain_balance_before > chain_balance_after,
            "hop-protocol chain balance"
        );
    }
}

#[derive(Debug, serde::Deserialize)]
struct TestData {
    block: BlockHeader,
    proof: ProofRequest,
}

#[tokio::test]
async fn patricia_validator() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
               "function testPatricia(address account, bytes32 storageKey, bytes calldata proofData) external returns (bytes32 stateRoot, bytes32 storageValue)",
        ])
        .expect("parse abi");

    let shared_state = get_shared_state().await.lock().unwrap();
    sync!(shared_state);

    let mut cumulative_gas = U256::zero();
    let mut samples = 0;
    for entry in std::fs::read_dir("tests/patricia/").unwrap() {
        let path = entry.expect("path").path();
        let file = File::open(&path).expect("file");
        let reader = BufReader::new(file);
        let test_data: TestData = serde_json::from_reader(reader).expect("json");
        let block_header = test_data.block;
        let proof = test_data.proof;
        let account = proof.address;

        for storage_proof in proof.storage_proof {
            let storage_key = storage_proof.key;
            let proof_data: Bytes =
                Bytes::from(marshal_proof(&proof.account_proof, &storage_proof.proof));
            let calldata = abi
                .function("testPatricia")
                .unwrap()
                .encode_input(&[
                    account.into_token(),
                    storage_key.into_token(),
                    proof_data.into_token(),
                ])
                .expect("calldata");

            let req = serde_json::json!([
                {
                    "to": "0x00000000000000000000000000000000000f0000",
                    "data": Bytes::from(calldata),
                },
                "latest"
            ]);

            let result: Result<Bytes, String> =
                jsonrpc_request(&shared_state.ro.l1_node, "eth_call", &req).await;
            let error_expected = storage_proof.value.is_zero();
            if result.is_err() != error_expected {
                log::error!("{:?} {:?} {:?}", result.clone().err(), storage_proof, path);
            }

            assert_eq!(result.is_err(), error_expected);
            if !error_expected {
                let res = result.unwrap();
                log::debug!("{}", res);
                let mut res = abi
                    .function("testPatricia")
                    .unwrap()
                    .decode_output(res.as_ref())
                    .expect("decode output");
                let storage_value = H256::from_token(res.pop().unwrap()).expect("bytes");
                let state_root = H256::from_token(res.pop().unwrap()).expect("bytes");

                assert_eq!(state_root, block_header.state_root, "state_root");
                assert_eq!(
                    U256::from(storage_value.as_ref()),
                    storage_proof.value,
                    "storage_value"
                );

                let gas_estimate: U256 =
                    jsonrpc_request(&shared_state.ro.l1_node, "eth_estimateGas", &req)
                        .await
                        .expect("estimateGas");
                // remove 'tx' cost
                cumulative_gas += gas_estimate - 21_000;
                samples += 1;
            }
        }
    }

    log::info!(
        "patricia_cumulative_gas={} samples={} avg={}",
        cumulative_gas,
        samples,
        cumulative_gas / samples
    );
}

#[tokio::test]
async fn witness_verifier() {
    init_logger();

    let shared_state = get_shared_state().await.lock().unwrap();

    shared_state.sync().await;
    shared_state.mine().await;

    // transfer ETH to self
    let tx_nonce: U256 = shared_state
        .request_l2(
            "eth_getTransactionCount",
            (shared_state.ro.l2_wallet.address(), "latest"),
        )
        .await
        .expect("nonce");
    let to = shared_state.ro.l2_wallet.address();
    let value = U256::from(1u64);
    let tx = shared_state.sign_l2(to, value, tx_nonce, vec![]).await;

    shared_state.mine_block(Some(vec![tx])).await;

    let block_num: U64 = shared_state
        .request_l2("eth_blockNumber", ())
        .await
        .expect("blockNumber");
    let witness = shared_state
        .request_witness(&block_num)
        .await
        .expect("witness");
    log::debug!("{:#?} input_len={}", witness, witness.input.as_ref().len());

    let abi = AbiParser::default()
        .parse(&[
               "function testPublicInput(uint256 zeta, bytes calldata witness) external returns (uint256, uint256, uint256)",
        ])
        .expect("parse abi");
    let calldata = abi
        .function("testPublicInput")
        .unwrap()
        .encode_input(&[witness.randomness.into_token(), witness.input.into_token()])
        .expect("calldata");

    let req = serde_json::json!([
        {
            "to": "0x00000000000000000000000000000000000f0000",
            "data": Bytes::from(calldata),
        },
        "latest"
    ]);

    // verify that it 'runs'
    let result: U64 = shared_state
        .request_l1("eth_estimateGas", &req)
        .await
        .expect("estimateGas");
    log::info!("gas={}", result);

    let result: Bytes = shared_state
        .request_l1("eth_call", &req)
        .await
        .expect("eth_call");
    let mut result = abi
        .function("testPublicInput")
        .unwrap()
        .decode_output(result.as_ref())
        .expect("decode output");
    let pi = U256::from_token(result.pop().unwrap()).expect("U256");
    let lagrange = U256::from_token(result.pop().unwrap()).expect("U256");
    let vanish = U256::from_token(result.pop().unwrap()).expect("U256");

    log::info!("vanish: {} lagrange: {} pi: {}", vanish, lagrange, pi);
}

#[tokio::test]
async fn test_sstore_regression() {
    init_logger();

    let shared_state = get_shared_state().await.lock().unwrap();

    // test for: https://github.com/privacy-scaling-explorations/zkevm-chain/issues/5
    // CODESIZE
    // CODESIZE
    // SSTORE
    let tx = serde_json::json!([
        {
            "data": "0x383855",
        },
        "latest"
    ]);
    let _: U64 = shared_state
        .request_l2("eth_estimateGas", &tx)
        .await
        .expect("should not crash");
}
