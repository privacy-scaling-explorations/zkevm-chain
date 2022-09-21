use coordinator::shared_state::SharedState;
use coordinator::utils::*;
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
use tokio::sync::Mutex;
use tokio::sync::OnceCell;
use zkevm_common::json_rpc::jsonrpc_request;
use zkevm_common::json_rpc::jsonrpc_request_client;

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
    ($tx_hash:expr, $url:expr) => {{
        let mut resp: Option<TransactionReceipt> = None;

        while (resp.is_none()) {
            resp = match jsonrpc_request($url, "eth_getTransactionReceipt", [$tx_hash]).await {
                Ok(val) => Some(val),
                Err(_) => None,
            };
        }

        let receipt = resp.unwrap();
        if receipt.status.unwrap() != U64::from(1) {
            panic!("transaction reverted");
        }

        receipt
    }};
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
            $shared_state
                .finalize_blocks()
                .await
                .expect("finalize_blocks");
            sync!($shared_state);
            while $shared_state.rw.lock().await.l2_message_queue.len() != 0 {
                $shared_state.relay_to_l1().await;
                sync!($shared_state);
            }
        }
    };
}

macro_rules! sleep {
    ($ms:expr) => {{
        use tokio::time::{sleep, Duration};
        sleep(Duration::from_millis($ms)).await;
    }};
}

macro_rules! await_state {
    () => {
        get_shared_state().await.lock().await
    };
}

fn init_logger() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .is_test(var("TEST_VERBOSE").is_err())
        .try_init();
}

static ONCE: OnceCell<Mutex<SharedState>> = OnceCell::const_new();

async fn get_shared_state() -> &'static Mutex<SharedState> {
    ONCE.get_or_init(|| async {
        let shared_state = SharedState::from_env_for_tests().await;
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
    let shared_state = await_state!();
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
            expected_balance += value;
            shared_state
                .transaction_to_l1(Some(shared_state.ro.l1_bridge_addr), value, calldata)
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
            assert!(found, "message id should exist");
        }

        sleep!(1000);
        let balance: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }

    finalize_chain!(shared_state);
}

#[tokio::test]
async fn native_withdraw() {
    init_logger();

    let abi = zkevm_abi();
    let shared_state = await_state!();
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
        for _ in 0..4 {
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
            expected_balance += value;
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

        shared_state
            .mine_block(Some(&txs))
            .await
            .expect("mine_block");
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
            assert!(found, "message id should exist");
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

#[ignore]
#[tokio::test]
async fn hop_deposit() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            // hop-protocol
            "function sendToL2(uint256 chainId, address recipient, uint256 amount, uint256 amountOutMin, uint256 deadline, address relayer, uint256 relayerFee)",
        ])
        .expect("parse abi");

    let shared_state = await_state!();

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

        shared_state
            .transaction_to_l1(Some(hop), amount, calldata)
            .await;
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

    finalize_chain!(shared_state);
}

#[ignore]
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
    let shared_state = await_state!();

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
            .transaction_to_l2(Some(hop), amount, calldata)
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
            .transaction_to_l2(Some(hop), U256::zero(), calldata)
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

#[tokio::test]
async fn native_deposit_revert() {
    init_logger();

    let abi = zkevm_abi();
    let shared_state = await_state!();
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
        let mut tx_nonce: U256 = jsonrpc_request(
            &shared_state.ro.l1_node,
            "eth_getTransactionCount",
            (shared_state.ro.l1_wallet.address(), "latest"),
        )
        .await
        .expect("nonce");

        let mut txs = Vec::new();
        for i in 0..30 {
            let should_revert = i % 2 == 0;
            let from = shared_state.ro.l1_wallet.address();
            let to = match should_revert {
                true => shared_state.ro.l2_message_deliverer_addr,
                false => receiver,
            };
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
            if !should_revert {
                expected_balance += value;
            }

            txs.push(
                sign_transaction_l1(
                    &shared_state.ro.http_client,
                    &shared_state.ro.l1_node,
                    &shared_state.ro.l1_wallet,
                    Some(shared_state.ro.l1_bridge_addr),
                    value,
                    calldata,
                    tx_nonce,
                )
                .await,
            );

            tx_nonce = tx_nonce + 1;
        }

        let mut tx_hashes = Vec::new();
        for raw_tx in &txs {
            let resp: Result<H256, String> = jsonrpc_request_client(
                5000,
                &shared_state.ro.http_client,
                &shared_state.ro.l1_node,
                "eth_sendRawTransaction",
                [raw_tx],
            )
            .await;

            tx_hashes.push(resp.unwrap());
        }

        for tx_hash in tx_hashes {
            wait_for_tx!(tx_hash, &shared_state.ro.l1_node);
        }
    }

    sync!(shared_state);

    // verify that all valid deposits are picked up
    {
        for (i, id) in deposits.iter().enumerate() {
            let found = shared_state
                .rw
                .lock()
                .await
                .l2_delivered_messages
                .iter()
                .any(|e| e == id);

            let should_revert = i % 2 == 0;
            assert_eq!(should_revert, !found, "message id should exist");
        }

        sleep!(1000);
        let balance: U256 = jsonrpc_request(
            &shared_state.ro.l2_node,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }

    finalize_chain!(shared_state);
}

#[tokio::test]
async fn zero_eth_transfer() {
    let shared_state = await_state!();
    let tx_hash = shared_state
        .transaction_to_l2(
            Some(shared_state.ro.l2_wallet.address()),
            U256::zero(),
            vec![],
        )
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    wait_for_tx!(tx_hash, &shared_state.ro.l2_node);

    finalize_chain!(shared_state);
}

#[ignore]
#[tokio::test]
async fn keccak() {
    let shared_state = await_state!();
    let bytecode = vec![
        0x60, 0x0b, 0x38, 0x03, 0x80, 0x60, 0x0b, 0x3d, 0x39, 0x3d, 0xf3, 0x60, 0x01, 0x60, 0xff,
        0x20, 0x00,
    ];
    let deploy_tx_hash = shared_state
        .transaction_to_l2(None, U256::zero(), bytecode)
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    shared_state.rw.lock().await.config_dummy_proof = true;
    finalize_chain!(shared_state);

    let deploy_receipt = wait_for_tx!(deploy_tx_hash, &shared_state.ro.l2_node);
    let contract_addr = deploy_receipt.contract_address;
    let tx_hash = shared_state
        .transaction_to_l2(contract_addr, U256::zero(), vec![])
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    wait_for_tx!(tx_hash, &shared_state.ro.l2_node);
    shared_state.rw.lock().await.config_dummy_proof = false;
    shared_state.rw.lock().await.config_mock_prover = true;
    finalize_chain!(shared_state);
    shared_state.rw.lock().await.config_mock_prover = false;
}
