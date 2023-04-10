mod common;

use crate::common::get_shared_state;
use crate::common::zkevm_abi;
use ethers_core::abi::encode;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::H256;
use ethers_core::types::U256;
use ethers_core::utils::keccak256;
use ethers_signers::Signer;
use zkevm_common::json_rpc::jsonrpc_request;

#[tokio::test]
async fn native_withdraw() {
    let abi = zkevm_abi();
    let shared_state = await_state!();
    let mut messages: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.config.lock().await.l1_rpc_url,
        "eth_getBalance",
        (receiver, "latest"),
    )
    .await
    .expect("eth_getBalance");

    shared_state.sync().await;
    shared_state.mine().await;

    {
        let mut tx_nonce: U256 = jsonrpc_request(
            &shared_state.config.lock().await.l2_rpc_url,
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
                        Some(shared_state.ro.l2_message_dispatcher_addr),
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
            &shared_state.config.lock().await.l1_rpc_url,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }
}
