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
use std::fs::read_dir;
use std::fs::File;
use std::io::Read;
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
            .transaction_to_l2(None, U256::zero(), $DEPLOY_CODE, None)
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
                None,
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
    let items = read_dir("../build/contracts/plonk-verifier/");
    if items.is_err() {
        return;
    }
    for item in items.unwrap() {
        let item = item.unwrap();
        let path = item.path();
        let file_name = item.file_name().into_string().unwrap();
        let address = file_name.split('-').last().unwrap();
        let mut file = File::open(&path).expect("open");
        let mut deploy_code = String::from("0x600b380380600b3d393df3");
        file.read_to_string(&mut deploy_code).expect("read");
        println!("{path:?} {address}");
        deploy_l1!(Bytes::from_str(&deploy_code).unwrap().to_vec(), address);
    }
}
