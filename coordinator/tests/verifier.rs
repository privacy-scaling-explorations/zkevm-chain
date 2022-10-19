mod common;

use crate::common::ContractArtifact;
use coordinator::shared_state::SharedState;
use coordinator::utils::*;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Token;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Block;
use ethers_core::types::Bytes;
use ethers_core::types::Transaction;
use ethers_core::types::H256;
use ethers_core::types::U256;
use lzma::LzmaReader;
use std::fs::File;

const COLUMNS: [&str; 11] = [
    "q_block_table",
    "block_table",
    "q_tx_table",
    "tx_table.id",
    "tx_table.tag",
    "tx_table.index",
    "tx_table.value",
    "raw_public_inputs",
    "rpi_rlc_acc",
    "rand_rpi",
    "q_end",
];

#[derive(Debug, serde::Deserialize)]
struct PublicInputs {
    max_txs: U256,
    max_calldata: U256,
    // rand_rpi: U256,
    chain_id: U256,
    // rpi_rlc: U256,
    // state_root: U256,
    state_root_prev: U256,
}

#[derive(Debug, serde::Deserialize)]
struct TestData {
    block: Block<Transaction>,
    block_hashes: Vec<H256>,
    rows: Vec<Vec<U256>>,
    public_inputs: PublicInputs,
}

#[tokio::test]
async fn witness_verifier() {
    let abi = AbiParser::default()
        .parse(&[
               "function Error(string)",
               "function testPublicInput(uint256 MAX_TXS, uint256 MAX_CALLDATA, uint256 chainId, uint256 parentStateRoot, bytes calldata witness) external returns (uint256[])",
        ])
        .expect("parse abi");
    let shared_state = SharedState::from_env().await;
    shared_state.init().await;

    for entry in std::fs::read_dir("tests/verifier/").unwrap() {
        let path = entry.expect("path").path();
        let file = File::open(&path).expect("file");
        let reader = LzmaReader::new_decompressor(file).unwrap();
        let test_data: TestData = serde_json::from_reader(reader).expect("json");

        let witness: Bytes = encode_verifier_witness(
            &test_data.block,
            test_data.block_hashes.as_slice(),
            &test_data.public_inputs.chain_id.as_u64(),
        )
        .expect("encode_verifier_witness")
        .into();

        let calldata = abi
            .function("testPublicInput")
            .unwrap()
            .encode_input(&[
                test_data.public_inputs.max_txs.into_token(),
                test_data.public_inputs.max_calldata.into_token(),
                test_data.public_inputs.chain_id.into_token(),
                test_data.public_inputs.state_root_prev.into_token(),
                witness.into_token(),
            ])
            .expect("calldata");

        println!("{:?}", path);

        let trace = ContractArtifact::load("ZkEvmTest")
            .l1_trace(&Bytes::from(calldata), &shared_state)
            .await
            .unwrap();
        let mut result = abi
            .function("testPublicInput")
            .unwrap()
            .decode_output(trace.return_value.as_ref())
            .expect("decode output");
        let table: Vec<Token> = result.pop().unwrap().into_array().unwrap();

        assert_eq!(test_data.rows.len() * 11, table.len(), "# rows");

        for (i, token) in table.iter().enumerate() {
            let tag = COLUMNS[i % COLUMNS.len()];
            let value: U256 = token.clone().into_uint().unwrap();
            if i % COLUMNS.len() == 0 {
                // start of new row
                println!("row({})", i / COLUMNS.len());
            }
            println!("{:4}({:17})={:064x}", i, tag, value);
            let row = &test_data.rows[i / 11];
            let expected = row[i % COLUMNS.len()];
            //if tag != "rpi_rlc_acc" && tag != "rand_rpi" {
            assert_eq!(
                expected, value,
                "{:?}:{} expected={:064x} has={:064x}",
                path, tag, expected, value
            );
            //}
        }

        println!("{:?}: gas={}", path, trace.gas);
    }
}
