mod commitment;
mod common;

use crate::commitment::test_public_commitment;
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
use rand::rngs::OsRng;
use rand::Rng;
use zkevm_common::json_rpc::jsonrpc_request;
use zkevm_common::json_rpc::jsonrpc_request_client;
use zkevm_common::prover::Proofs;

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

#[tokio::test]
async fn zero_eth_transfer() {
    let shared_state = await_state!();
    let tx_hash = shared_state
        .transaction_to_l2(
            Some(shared_state.ro.l2_wallet.address()),
            U256::zero(),
            vec![],
            None,
        )
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    wait_for_tx!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);

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
        .transaction_to_l2(None, U256::zero(), bytecode, None)
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    shared_state.config.lock().await.dummy_prover = true;
    finalize_chain!(shared_state);

    let deploy_receipt = wait_for_tx!(deploy_tx_hash, &shared_state.config.lock().await.l2_rpc_url);
    let contract_addr = deploy_receipt.contract_address;
    let tx_hash = shared_state
        .transaction_to_l2(contract_addr, U256::zero(), vec![], None)
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    wait_for_tx!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);
    shared_state.config.lock().await.dummy_prover = false;
    shared_state.config.lock().await.mock_prover = true;
    finalize_chain!(shared_state);
    shared_state.config.lock().await.mock_prover = false;
}

#[tokio::test]
async fn l1_l2_sync_test() {
    let abi = zkevm_abi();
    let shared_state = await_state!();
    let mut deposits: Vec<H256> = Vec::new();

    for _ in 0..2 {
        let l1_bridge_addr = Some(shared_state.config.lock().await.l1_bridge);
        // create deposits
        let from = shared_state.ro.l1_wallet.address();
        let to = Address::zero();
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

        // create a block with zero logs before the bridge deposit
        let _ = shared_state
            .transaction_to_l1(
                Some(shared_state.ro.l2_wallet.address()),
                U256::zero(),
                vec![],
            )
            .await
            .expect("receipt");
        // deposit
        shared_state
            .transaction_to_l1(l1_bridge_addr, value, calldata)
            .await
            .expect("receipt");
    }

    sync!(shared_state);

    // verify that all deposit are picked up
    for id in deposits {
        let mut i = 0;
        shared_state
            .rw
            .lock()
            .await
            .l2_delivered_messages
            .iter()
            .for_each(|e| {
                if e == &id {
                    i += 1
                }
            });
        assert!(i == 1, "message id should exist and only once");
    }

    finalize_chain!(shared_state);
}

#[ignore]
#[tokio::test]
async fn finalize_chain() {
    let shared_state = await_state!();
    sync!(shared_state);
    shared_state.mine().await;
    finalize_chain!(shared_state);
}

// COORDINATOR_MOCK_PROVER=true ./scripts/test_prover.sh --ignored test_pi_commitment
#[ignore]
#[tokio::test]
async fn test_pi_commitment() {
    let shared_state = await_state!();
    sync!(shared_state);
    shared_state.mine().await;

    let mut tx_nonce: U256 = jsonrpc_request(
        &shared_state.config.lock().await.l2_rpc_url,
        "eth_getTransactionCount",
        (shared_state.ro.l2_wallet.address(), "latest"),
    )
    .await
    .expect("nonce");
    let mut txs = vec![];
    for i in 0..3 {
        let to = if i % 2 == 0 {
            Some(shared_state.ro.l2_wallet.address())
        } else {
            None
        };
        let value = U256::from(OsRng.gen::<u32>());
        let mut input: Vec<u8> = Vec::new();
        while input.len() < 1234 {
            if to.is_none() {
                input.push(0);
            } else {
                input.push(OsRng.gen::<u8>());
            }
        }
        txs.push(shared_state.sign_l2(to, value, tx_nonce, input).await);
        tx_nonce = tx_nonce + 1;
    }

    let block = shared_state
        .mine_block(Some(&txs))
        .await
        .expect("mine_block");
    let block_num = block.number.unwrap();
    println!("{block:#?}");

    loop {
        let proofs: Option<Proofs> = shared_state
            .request_proof(&block_num)
            .await
            .expect("proofs");
        match proofs {
            None => continue,
            Some(proof) => {
                log::info!("{:#?}", &proof);
                let proof_result = proof.circuit;
                let table = test_public_commitment(&shared_state, &block_num, &proof.config)
                    .await
                    .expect("test_public_commitment");
                assert_eq!(proof_result.instance, table, "public inputs");

                break;
            }
        }
    }

    finalize_chain!(shared_state, true);
}
