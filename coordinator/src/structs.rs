use ethers_core::abi::encode;
use ethers_core::abi::Tokenizable;
use ethers_core::types::{Address, Bytes, H256, U256, U64};
use ethers_core::utils::keccak256;

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ForkchoiceStateV1 {
    #[serde(rename = "headBlockHash")]
    pub head_block_hash: H256,
    #[serde(rename = "safeBlockHash")]
    pub safe_block_hash: H256,
    #[serde(rename = "finalizedBlockHash")]
    pub finalized_block_hash: H256,
}

#[derive(Clone, Debug)]
pub struct MessageBeacon {
    pub id: H256,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub fee: U256,
    pub deadline: U256,
    pub nonce: U256,
    pub calldata: Vec<u8>,
}

impl MessageBeacon {
    /// calculates the storage address for `self`
    pub fn storage_slot(&self) -> H256 {
        let mut buf: Vec<u8> = Vec::with_capacity(64);
        let sig = 0x31df76a4_u32.to_be_bytes();

        buf.resize(28, 0);
        buf.extend(sig);
        buf.extend(self.id.as_ref());

        keccak256(buf).into()
    }

    /// Calculate message id.
    pub fn gen_id(&self) -> H256 {
        let id: H256 = keccak256(encode(&[
            self.from.into_token(),
            self.to.into_token(),
            self.value.into_token(),
            self.fee.into_token(),
            self.deadline.into_token(),
            self.nonce.into_token(),
            Bytes::from(self.calldata.clone()).into_token(),
        ]))
        .into();

        id
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SealBlockRequest<'a> {
    pub parent: &'a H256,
    pub random: &'a H256,
    pub timestamp: &'a U64,
    pub transactions: Option<&'a Vec<Bytes>>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BlockHeader {
    #[serde(rename = "parentHash")]
    pub parent_hash: H256,
    pub hash: H256,
    pub number: U64,
    #[serde(rename = "stateRoot")]
    pub state_root: H256,
    // add missing fields if required
}

// https://eips.ethereum.org/EIPS/eip-1186
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct MerkleProofRequest {
    pub address: Address,
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<Bytes>,
    pub balance: U256,
    #[serde(rename = "codeHash")]
    pub code_hash: H256,
    pub nonce: U256,
    #[serde(rename = "storageHash")]
    pub storage_hash: H256,
    #[serde(rename = "storageProof")]
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct StorageProof {
    pub key: H256,
    pub value: U256,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Witness {
    pub randomness: U256,
    pub input: Bytes,
}
