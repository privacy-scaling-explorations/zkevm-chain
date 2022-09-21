#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Proofs {
    pub state_proof: eth_types::Bytes,
    pub evm_proof: eth_types::Bytes,
    /// proofing time
    pub duration: u64,
    /// k of parameter file
    pub k: u8,
    /// Gas used. Determines the upper ceiling for circuit parameters.
    pub gas: u64,
    /// CircuitInputBuilder: block.randomness
    pub randomness: eth_types::Bytes,
}

impl std::fmt::Debug for Proofs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proofs")
            .field("state_proof", &format!("{}", &self.state_proof))
            .field("evm_proof", &format!("{}", &self.evm_proof))
            .field("duration", &self.duration)
            .field("k", &self.k)
            .finish()
    }
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofRequestOptions {
    /// the block number
    pub block: u64,
    /// the rpc url
    pub rpc: String,
    /// retry proof computation if error
    pub retry: bool,
    /// parameter file to use
    pub param: String,
    /// Only use MockProver if true.
    #[serde(default = "default_bool")]
    pub mock: bool,
}

impl PartialEq for ProofRequestOptions {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block && self.rpc == other.rpc && self.param == other.param
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofRequest {
    pub options: ProofRequestOptions,
    pub result: Option<Result<Proofs, String>>,
    /// A counter to keep track of changes of the `result` field
    pub edition: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeInformation {
    pub id: String,
    pub tasks: Vec<ProofRequest>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeStatus {
    pub id: String,
    /// The current active task this instance wants to obtain or is working on.
    pub task: Option<ProofRequestOptions>,
    /// `true` if this instance started working on `task`
    pub obtained: bool,
}

fn default_bool() -> bool {
    false
}
