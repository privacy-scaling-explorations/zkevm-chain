use coordinator::shared_state::SharedState;
use coordinator::structs::BlockHeader;
use ethers_core::abi::Abi;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Token;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Bytes;
use ethers_core::types::U256;
use ethers_core::types::U64;
use ethers_signers::Signer;
use std::fs::File;
use std::io::BufReader;
use zkevm_common::prover::CircuitConfig;

fn get_abi() -> Abi {
    AbiParser::default()
        .parse(&[
               "function testPublicInputCommitment(uint256 MAX_TXS, uint256 MAX_CALLDATA, uint256 chainId, uint256 parentStateRoot, bytes calldata witness) returns (uint256[])",
        ])
        .expect("parse abi")
}

pub(crate) async fn test_public_commitment(
    state: &SharedState,
    block_num: &U64,
    circuit_config: &CircuitConfig,
) -> Result<Vec<U256>, String> {
    let prev_block: BlockHeader = state
        .request_l2("eth_getHeaderByNumber", [block_num - 1])
        .await
        .expect("prev_block");
    let witness = state.request_witness(block_num).await.expect("witness");
    let state_root_prev = U256::from(prev_block.state_root.as_ref());
    let chain_id = state.ro.l2_wallet.chain_id();
    let max_calldata = U256::from(circuit_config.max_calldata);
    let max_txs = U256::from(circuit_config.max_txs);

    let abi = get_abi();
    let test_fn = abi.function("testPublicInputCommitment").unwrap();
    let calldata = test_fn
        .encode_input(&[
            max_txs.into_token(),
            max_calldata.into_token(),
            chain_id.into_token(),
            state_root_prev.into_token(),
            witness.input.into_token(),
        ])
        .expect("calldata");

    let path = "../build/contracts/combined.json";
    let file = File::open(path).unwrap_or_else(|err| panic!("{}: {}", &path, err));
    let reader = BufReader::new(file);
    let combined: serde_json::Value = serde_json::from_reader(reader).unwrap();
    let bin_runtime = combined
        .get("contracts")
        .unwrap()
        .get("contracts/tests/ZkEvmTest.sol:ZkEvmTest")
        .unwrap()
        .get("bin-runtime")
        .unwrap();

    let resp: Bytes = state
        .request_l1(
            "eth_call",
            serde_json::json!([
                {
                    "to": "0x00000000000000000000000000000000000f0000",
                    "data": Bytes::from(calldata),
                },
                "latest",
                {
                    "0x00000000000000000000000000000000000f0000": {
                        "code": format!("0x{}", bin_runtime.as_str().unwrap()),
                    },
                }
            ]),
        )
        .await?;
    let mut result = test_fn.decode_output(resp.as_ref()).expect("decode output");
    let table: Vec<Token> = result.pop().unwrap().into_array().unwrap();
    let ret = table
        .iter()
        .map(|e| e.clone().into_uint().unwrap())
        .collect();

    Ok(ret)
}
