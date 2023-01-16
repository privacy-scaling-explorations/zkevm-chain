mod common;

use crate::common::get_shared_state;
use ethers_core::types::Address;
use ethers_core::types::Block;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::H256;
use ethers_core::types::U256;
use std::str::FromStr;
use zkevm_common::json_rpc::jsonrpc_request;

#[tokio::test]
async fn worst_case_smod() {
    let shared_state = await_state!();
    let latest_block: Block<H256> = shared_state
        .request_l2("eth_getBlockByNumber", ("latest", false))
        .await
        .unwrap();
    let block_gas_limit = latest_block.gas_limit;
    let tx_hash = shared_state
        .transaction_to_l2(
            Some(Address::from_str("0x0000000000000000000000000000000000100001").unwrap()),
            U256::zero(),
            vec![],
            Some(block_gas_limit),
        )
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    let receipt = wait_for_tx_no_panic!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);
    assert_eq!(receipt.gas_used.expect("gas_used"), block_gas_limit);
    finalize_chain!(shared_state);
}

#[tokio::test]
async fn worst_case_mload() {
    let shared_state = await_state!();
    let latest_block: Block<H256> = shared_state
        .request_l2("eth_getBlockByNumber", ("latest", false))
        .await
        .unwrap();
    let block_gas_limit = latest_block.gas_limit;
    let tx_hash = shared_state
        .transaction_to_l2(
            Some(Address::from_str("0x0000000000000000000000000000000000100002").unwrap()),
            U256::zero(),
            vec![],
            Some(block_gas_limit),
        )
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    let receipt = wait_for_tx_no_panic!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);
    assert_eq!(receipt.gas_used.expect("gas_used"), block_gas_limit);
    finalize_chain!(shared_state);
}

#[tokio::test]
async fn worst_case_keccak_0_32() {
    let shared_state = await_state!();
    let latest_block: Block<H256> = shared_state
        .request_l2("eth_getBlockByNumber", ("latest", false))
        .await
        .unwrap();
    let block_gas_limit = latest_block.gas_limit;
    let tx_hash = shared_state
        .transaction_to_l2(
            Some(Address::from_str("0x0000000000000000000000000000000000100003").unwrap()),
            U256::zero(),
            vec![],
            Some(block_gas_limit),
        )
        .await
        .expect("tx_hash");
    shared_state.mine().await;
    let receipt = wait_for_tx_no_panic!(tx_hash, &shared_state.config.lock().await.l2_rpc_url);
    assert_eq!(receipt.gas_used.expect("gas_used"), block_gas_limit);
    finalize_chain!(shared_state);
}
