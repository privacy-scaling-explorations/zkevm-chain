mod common;

use crate::common::get_shared_state;
use crate::common::proxy_abi;
use crate::common::ContractArtifact;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::U256;
use ethers_core::types::U64;
use serde::Deserialize;
use std::fs::read_dir;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

macro_rules! deploy_l1 {
    ($DEPLOY_CODE:expr, $ADDRESS:expr) => {{
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .is_test(true)
                .try_init();
        let abi = proxy_abi();
        let shared_state = await_state!();

        let receipt = shared_state
            .transaction_to_l1(None, U256::zero(), $DEPLOY_CODE)
            .await
            .expect("receipt");
        assert!(receipt.status.unwrap() == U64::from(1));

        let contract_addr = receipt.contract_address.expect("contract_address");
        let calldata = abi
            .function("upgrade")
            .unwrap()
            .encode_input(&[contract_addr.into_token()])
            .expect("calldata");

        let receipt = shared_state
            .transaction_to_l1(
                Some(Address::from_str($ADDRESS).unwrap()),
                U256::zero(),
                calldata,
            )
            .await
            .expect("receipt");
        assert!(receipt.status.unwrap() == U64::from(1));
    }};
}

macro_rules! deploy_l2 {
    ($DEPLOY_CODE:expr, $ADDRESS:expr) => {{
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .is_test(true)
                .try_init();
        let abi = proxy_abi();
        let shared_state = await_state!();

        let tx_hash = shared_state
            .transaction_to_l2(None, U256::zero(), $DEPLOY_CODE)
            .await
            .expect("tx_hash");
        shared_state.mine().await;

        let receipt: TransactionReceipt = shared_state
            .request_l2("eth_getTransactionReceipt", [tx_hash])
            .await
            .expect("receipt");
        assert!(receipt.status.unwrap() == U64::from(1));

        let contract_addr = receipt.contract_address.expect("contract_address");
        let calldata = abi
            .function("upgrade")
            .unwrap()
            .encode_input(&[contract_addr.into_token()])
            .expect("calldata");

        let tx_hash = shared_state
            .transaction_to_l2(
                Some(Address::from_str($ADDRESS).unwrap()),
                U256::zero(),
                calldata,
            )
            .await
            .expect("tx_hash");
        shared_state.mine().await;

        let receipt: TransactionReceipt = shared_state
            .request_l2("eth_getTransactionReceipt", [tx_hash])
            .await
            .expect("receipt");
        assert!(receipt.status.unwrap() == U64::from(1));
    }};
}

macro_rules! code {
    ($NAME:expr) => {{
        ContractArtifact::load($NAME).bin.to_vec()
    }};
}

#[tokio::test]
async fn deploy_l1_bridge() {
    deploy_l1!(
        code!("ZkEvmL1Bridge"),
        "0x936a70c0b28532aa22240dce21f89a8399d6ac60"
    );
}

#[tokio::test]
async fn deploy_l1_optimism() {
    deploy_l1!(
        code!("L1OptimismBridge"),
        "0x936a70c0b28532aa22240dce21f89a8399d6ac61"
    );
}

// TODO: l2 gas limit not sufficient
#[ignore]
#[tokio::test]
async fn deploy_l2_bridge() {
    deploy_l2!(
        code!("ZkEvmL2MessageDeliverer"),
        "0x0000000000000000000000000000000000010000"
    );
    deploy_l2!(
        code!("ZkEvmL2MessageDispatcher"),
        "0x0000000000000000000000000000000000020000"
    );
}

// TODO: l2 gas limit not sufficient
#[ignore]
#[tokio::test]
async fn deploy_l2_optimism() {
    deploy_l2!(
        code!("L2OptimisimBridge"),
        "0x4200000000000000000000000000000000000007"
    );
}

#[tokio::test]
async fn deploy_l1_evm_verifier() {
    #[derive(Deserialize)]
    struct Data {
        runtime_code: Bytes,
        address: String,
    }

    let items = read_dir("../build/plonk-verifier/");
    if items.is_err() {
        return;
    }
    for item in items.unwrap() {
        let path = item.expect("path").path();
        let file = File::open(&path).expect("open");
        let data: Data = serde_json::from_reader(BufReader::new(file)).expect("json");
        let mut deploy_code = vec![
            0x60, 0x0b, 0x38, 0x03, 0x80, 0x60, 0x0b, 0x3d, 0x39, 0x3d, 0xf3,
        ];
        deploy_code.extend_from_slice(data.runtime_code.as_ref());
        println!("{:?} {}", path, data.address);
        deploy_l1!(deploy_code, &data.address);
    }
}
