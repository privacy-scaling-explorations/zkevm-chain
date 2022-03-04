use ethers_core::types::{Address, Bytes, H256, U256, U64};
use serde::Serialize;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct JsonRpcResponseError {
    pub jsonrpc: String,
    pub id: u64,
    pub error: JsonRpcError,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct JsonRpcRequest<T: Serialize> {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: T,
}

#[derive(serde::Deserialize)]
pub struct JsonRpcResponse<T> {
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ForkchoiceStateV1 {
    #[serde(rename = "headBlockHash")]
    pub head_block_hash: H256,
    #[serde(rename = "safeBlockHash")]
    pub safe_block_hash: H256,
    #[serde(rename = "finalizedBlockHash")]
    pub finalized_block_hash: H256,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Proofs {
    pub state_proof: Bytes,
    pub evm_proof: Bytes,
}

#[derive(Debug)]
pub struct L1MessageBeacon {
    pub id: H256,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub fee: U256,
    pub deadline: U256,
    pub nonce: U256,
    pub calldata: Vec<u8>,
}

#[derive(Debug, serde::Serialize)]
pub struct SealBlockRequest {
    pub parent: H256,
    pub random: H256,
    pub timestamp: U64,
    pub transactions: Option<Vec<Bytes>>,
}
