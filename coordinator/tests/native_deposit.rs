mod common;

use crate::common::get_shared_state;
use crate::common::zkevm_abi;
use coordinator::utils::*;
use ethers_core::abi::encode;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::H256;
use ethers_core::types::U256;
use ethers_core::types::U64;
use ethers_core::utils::keccak256;
use ethers_signers::Signer;
use zkevm_common::json_rpc::jsonrpc_request;
use zkevm_common::json_rpc::jsonrpc_request_client;

#[tokio::test]
async fn native_deposit() {
    let abi = zkevm_abi();
    let shared_state = await_state!();
    let mut deposits: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.config.lock().await.l2_rpc_url,
        "eth_getBalance",
        (receiver, "latest"),
    )
    .await
    .expect("eth_getBalance");
    let l1_bridge_addr = Some(shared_state.config.lock().await.l1_bridge);

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
                .transaction_to_l1(l1_bridge_addr, value, calldata)
                .await
                .expect("receipt");
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
            &shared_state.config.lock().await.l2_rpc_url,
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
async fn native_deposit_revert() {
    let abi = zkevm_abi();
    let shared_state = await_state!();
    let mut deposits: Vec<H256> = Vec::new();
    let receiver = Address::zero();
    let mut expected_balance: U256 = jsonrpc_request(
        &shared_state.config.lock().await.l2_rpc_url,
        "eth_getBalance",
        (receiver, "latest"),
    )
    .await
    .expect("eth_getBalance");

    {
        // create deposits
        let mut tx_nonce: U256 = jsonrpc_request(
            &shared_state.config.lock().await.l1_rpc_url,
            "eth_getTransactionCount",
            (shared_state.ro.l1_wallet.address(), "latest"),
        )
        .await
        .expect("nonce");
        let l1_bridge_addr = Some(shared_state.config.lock().await.l1_bridge);

        let mut txs: Vec<Bytes> = Vec::new();
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
                    &shared_state.config.lock().await.l1_rpc_url,
                    &shared_state.ro.l1_wallet,
                    l1_bridge_addr,
                    value,
                    calldata,
                    tx_nonce,
                )
                .await
                .expect("bytes"),
            );

            tx_nonce = tx_nonce + 1;
        }

        let mut tx_hashes = Vec::new();
        for raw_tx in &txs {
            let resp: Result<H256, String> = jsonrpc_request_client(
                RPC_REQUEST_TIMEOUT,
                &shared_state.ro.http_client,
                &shared_state.config.lock().await.l1_rpc_url,
                "eth_sendRawTransaction",
                [raw_tx],
            )
            .await;

            tx_hashes.push(resp.unwrap());
        }

        for tx_hash in tx_hashes {
            wait_for_tx!(tx_hash, &shared_state.config.lock().await.l1_rpc_url);
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
            &shared_state.config.lock().await.l2_rpc_url,
            "eth_getBalance",
            (receiver, "latest"),
        )
        .await
        .expect("eth_getBalance");
        assert_eq!(expected_balance, balance, "ETH balance");
    }

    finalize_chain!(shared_state);
}
