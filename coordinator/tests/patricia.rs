mod common;

use crate::common::ContractArtifact;
use coordinator::shared_state::SharedState;
use coordinator::structs::ProofRequest;
use coordinator::utils::marshal_proof;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Bytes;
use ethers_core::types::H256;
use ethers_core::types::U256;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, serde::Deserialize)]
struct BlockHeader {
    #[serde(rename = "stateRoot")]
    state_root: H256,
}

#[derive(Debug, serde::Deserialize)]
struct TestData {
    block: BlockHeader,
    proof: ProofRequest,
}

#[tokio::test]
async fn patricia_validator() {
    let abi = AbiParser::default()
        .parse(&[
               "function testPatricia(address account, bytes32 storageKey, bytes calldata proofData) external returns (bytes32 stateRoot, bytes32 storageValue)",
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
            let proof_data: Bytes =
                Bytes::from(marshal_proof(&proof.account_proof, &storage_proof.proof));
            let calldata = abi
                .function("testPatricia")
                .unwrap()
                .encode_input(&[
                    account.into_token(),
                    storage_key.into_token(),
                    proof_data.into_token(),
                ])
                .expect("calldata");

            let result = ContractArtifact::load("ZkEvmTest")
                .l1_trace(&Bytes::from(calldata), &shared_state)
                .await;
            let error_expected = storage_proof.value.is_zero();
            assert_eq!(
                result.is_err(),
                error_expected,
                "{:?} {:?} {:?}",
                result,
                storage_proof,
                path
            );
            if !error_expected {
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
    }

    let avg: u64 = cumulative_gas / samples;
    log::info!(
        "patricia_cumulative_gas={} samples={} avg={}",
        cumulative_gas,
        samples,
        avg
    );

    const MAX_DIFF: u64 = 1000;
    const KNOWN_AVG: u64 = 62569;
    if !((KNOWN_AVG - MAX_DIFF)..=(KNOWN_AVG + MAX_DIFF)).contains(&avg) {
        panic!(
            "patricia_validator: please update KNOWN_AVG ({}), new value: {}",
            KNOWN_AVG, avg
        );
    }
}
