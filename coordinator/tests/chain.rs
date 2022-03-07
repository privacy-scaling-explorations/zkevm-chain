use coordinator::shared_state::SharedState;
use coordinator::utils::jsonrpc_request;
use ethers_core::abi::encode;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::H256;
use ethers_core::types::U256;
use ethers_core::utils::keccak256;
use ethers_signers::Signer;
use std::time::Duration;
use tokio::time::sleep;

fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        .is_test(true)
        .try_init();
}

#[tokio::test]
async fn test_deposit() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            "function sendMessage(address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) external payable",
        ])
        .expect("parse abi");

    let shared_state = SharedState::from_env().await;
    shared_state.init().await;

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
            let value = U256::from(1);
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

    {
        // sync bridge and process events
        shared_state.sync().await;
        while shared_state.rw.lock().await.l1_message_queue.len() > 0 {
            shared_state.mine().await;
            shared_state.sync().await;
            // sleep a bit to avoid mining too fast (timestamp)
            sleep(Duration::from_millis(1000)).await;
        }
    }

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
