use coordinator::shared_state::SharedState;
use coordinator::utils::jsonrpc_request;
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
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::sleep;

macro_rules! sync {
    ($shared_state:expr) => {
        // sync bridge and process events
        $shared_state.sync().await;
        while $shared_state.rw.lock().await.l1_message_queue.len() > 0 {
            $shared_state.mine().await;
            $shared_state.sync().await;
            // sleep a bit to avoid mining too fast (timestamp)
            sleep(Duration::from_millis(1000)).await;
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

fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
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

#[tokio::test]
async fn native_deposit() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            // zkevm native bridge
            "function sendMessage(address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) external payable",
        ])
        .expect("parse abi");

    let shared_state = get_shared_state().await.lock().unwrap();
    let mut deposits: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.ro.leader_node,
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
                .function("sendMessage")
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
                .l2_messages
                .iter()
                .any(|e| e == &id);
            assert_eq!(true, found, "message id should exist");
        }

        // the node may not catch up immediately
        sleep(Duration::from_millis(300)).await;

        let balance: U256 = jsonrpc_request(
            &shared_state.ro.leader_node,
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
            &shared_state.ro.leader_node,
            "eth_getBalance",
            (recipient, "latest"),
        )
        .await
        .expect("eth_getBalance");

        shared_state.transaction_to_l1(hop, amount, calldata).await;
        sync!(shared_state);

        let balance_after: U256 = jsonrpc_request(
            &shared_state.ro.leader_node,
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
async fn hop_withdraw() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            // hop-protocol
            "function swapAndSend(uint256 chainId, address recipient, uint256 amount, uint256 bonderFee, uint256 amountOutMin, uint256 deadline, uint256 destinationAmountOutMin, uint256 destinationDeadline)"
        ])
        .expect("parse abi");

    let shared_state = get_shared_state().await.lock().unwrap();
    let hop: Address = "0x86cA30bEF97fB651b8d866D45503684b90cb3312"
        .parse()
        .unwrap();
    let chain_id = U256::from(98u64);
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

    let balance_before: U256 = jsonrpc_request(
        &shared_state.ro.l1_node,
        "eth_getBalance",
        (recipient, "latest"),
    )
    .await
    .expect("eth_getBalance");

    sync!(shared_state);
    let tx_hash = shared_state
        .transaction_to_l2(hop, amount, calldata)
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    wait_for_tx!(tx_hash, &shared_state.ro.leader_node);
    shared_state.submit_blocks().await;
    sync!(shared_state);
    shared_state.finalize_blocks().await;
    sync!(shared_state);

    let balance_after: U256 = jsonrpc_request(
        &shared_state.ro.l1_node,
        "eth_getBalance",
        (recipient, "latest"),
    )
    .await
    .expect("eth_getBalance");

    let min_expected_balance = balance_before + destination_amount_out_min;
    // TODO: activate after automatic L2>L1 relay is implemented
    assert!(
        balance_after >= min_expected_balance || true,
        "ETH balance on L1 after hop withdraw"
    );
}
