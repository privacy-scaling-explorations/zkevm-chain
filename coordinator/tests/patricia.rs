mod common;

use crate::common::ContractArtifact;
use coordinator::shared_state::SharedState;
use coordinator::structs::MerkleProofRequest;
use coordinator::utils::marshal_proof_single;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::H256;
use ethers_core::types::U256;
use std::env;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct BlockHeader {
    #[serde(rename = "stateRoot")]
    state_root: H256,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct TestData {
    block: BlockHeader,
    proof: MerkleProofRequest,
}

/// Can be used to create test-data fixtures.
#[ignore]
#[tokio::test]
async fn patricia_fixture() {
    let shared_state = SharedState::from_env().await;
    shared_state.init().await;
    let addr = env::var("ADDR")
        .expect("ADDR env var")
        .parse::<Address>()
        .expect("valid address");
    let block: BlockHeader = shared_state
        .request_l2("eth_getHeaderByNumber", ["latest"])
        .await
        .unwrap();
    let slots: Vec<String> = (0..18).map(|v| format! {"0x{v:064x}"}).collect();
    let proof: MerkleProofRequest = shared_state
        .request_l2("eth_getProof", (addr, slots, "latest"))
        .await
        .expect("eth_getProof");
    let test_data = TestData { block, proof };
    let addr = format!("{addr:?}");
    let file = File::create(format!("test-data-{}.json", addr.replace("0x", ""))).unwrap();
    serde_json::to_writer_pretty(file, &test_data).unwrap();
}

#[tokio::test]
async fn patricia_validator() {
    let abi = AbiParser::default()
        .parse(&[
               "function testPatricia(address account, bytes32 storageKey, bytes calldata accountProof, bytes calldata storageProof) external returns (bytes32 stateRoot, bytes32 storageValue)",
        ])
        .expect("parse abi");

    let shared_state = SharedState::from_env().await;
    shared_state.init().await;

    let mut cumulative_gas = 0;
    let mut samples = 0;
    for entry in std::fs::read_dir("tests/patricia/").unwrap() {
        let path = entry.expect("path").path();
        let file = File::open(&path).expect("file");
        let reader = BufReader::new(file);
        let test_data: TestData = serde_json::from_reader(reader).expect("json");
        let block_header = test_data.block;
        let proof = test_data.proof;
        let account = proof.address;

        for storage_proof in proof.storage_proof {
            let storage_key = storage_proof.key;
            let account_proof_data: Bytes = Bytes::from(marshal_proof_single(&proof.account_proof));
            let storage_proof_data: Bytes = Bytes::from(marshal_proof_single(&storage_proof.proof));
            let calldata = abi
                .function("testPatricia")
                .unwrap()
                .encode_input(&[
                    account.into_token(),
                    storage_key.into_token(),
                    account_proof_data.into_token(),
                    storage_proof_data.into_token(),
                ])
                .expect("calldata");

            let result = ContractArtifact::load("ZkEvmTest")
                .l1_trace(&Bytes::from(calldata), &shared_state)
                .await;
            assert!(result.is_ok(), "{result:?} {storage_proof:?} {path:?}");

            let trace = result.unwrap();
            let mut res = abi
                .function("testPatricia")
                .unwrap()
                .decode_output(trace.return_value.as_ref())
                .expect("decode output");
            let storage_value = H256::from_token(res.pop().unwrap()).expect("bytes");
            let state_root = H256::from_token(res.pop().unwrap()).expect("bytes");

            assert_eq!(state_root, block_header.state_root, "state_root");
            assert_eq!(
                U256::from(storage_value.as_ref()),
                storage_proof.value,
                "storage_value"
            );

            // remove 'tx' cost
            cumulative_gas += trace.gas - 21_000;
            samples += 1;
        }
    }

    let avg: u64 = cumulative_gas / samples;
    println!("patricia_cumulative_gas={cumulative_gas} samples={samples} avg={avg}");

    const MAX_DIFF: u64 = 1000;
    const KNOWN_AVG: u64 = 64256;
    if !((KNOWN_AVG - MAX_DIFF)..=(KNOWN_AVG + MAX_DIFF)).contains(&avg) {
        panic!("patricia_validator: please update KNOWN_AVG ({KNOWN_AVG}), new value: {avg}");
    }
}
