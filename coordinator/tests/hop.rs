mod common;

use crate::common::get_shared_state;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::U256;
use ethers_core::types::U64;
use zkevm_common::json_rpc::jsonrpc_request;

#[ignore]
#[tokio::test]
async fn hop_deposit() {
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
            &shared_state.config.lock().await.l2_rpc_url,
            "eth_getBalance",
            (recipient, "latest"),
        )
        .await
        .expect("eth_getBalance");

        shared_state
            .transaction_to_l1(Some(hop), amount, calldata)
            .await
            .expect("receipt");
        sync!(shared_state);

        let balance_after: U256 = jsonrpc_request(
            &shared_state.config.lock().await.l2_rpc_url,
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
        &shared_state.config.lock().await.l1_rpc_url,
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
            .transaction_to_l2(Some(hop), amount, calldata, None)
            .await
            .expect("tx_hash");
        shared_state.mine().await;
        wait_for_tx!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);
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
            .transaction_to_l2(Some(hop), U256::zero(), calldata, None)
            .await
            .expect("tx_hash_commit");
        shared_state.mine().await;
        wait_for_tx!(tx_hash_commit, &shared_state.config.lock().await.l2_rpc_url);
    }

    finalize_chain!(shared_state);

    {
        // verify that the L2 > L1 message was executed successfully
        let chain_balance_after: U256 = jsonrpc_request(
            &shared_state.config.lock().await.l1_rpc_url,
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
