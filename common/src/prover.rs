use eth_types::{Bytes, U256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProofResult {
    /// The halo2 transcript
    pub proof: Bytes,
    /// Public inputs for the proof
    pub instance: Vec<U256>,
    /// k of circuit parameters
    pub k: u8,
    /// Randomness used
    pub randomness: Bytes,
    /// Proofing time
    pub duration: u32,
    /// Circuit name / identifier
    pub label: String,
}

impl std::fmt::Debug for ProofResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("proof", &format!("{}", &self.proof))
            .field("instance", &self.instance)
            .field("k", &self.k)
            .field("randomness", &format!("{}", &self.randomness))
            .field("duration", &self.duration)
            .finish()
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Proofs {
    /// Circuit configuration used
    pub config: CircuitConfig,
    // Proof result for circuit
    pub circuit: ProofResult,
    /// Aggregation proof for circuit, if requested
    pub aggregation: ProofResult,
    /// Gas used. Determines the upper ceiling for circuit parameters
    pub gas: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProofRequestOptions {
    /// The name of the circuit.
    /// "super", "pi"
    pub circuit: String,
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
    /// Additionaly aggregates the circuit proof if true
    #[serde(default = "default_bool")]
    pub aggregate: bool,
}

impl PartialEq for ProofRequestOptions {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block
            && self.rpc == other.rpc
            && self.param == other.param
            && self.circuit == other.circuit
            && self.mock == other.mock
            && self.aggregate == other.aggregate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    pub options: ProofRequestOptions,
    pub result: Option<Result<Proofs, String>>,
    /// A counter to keep track of changes of the `result` field
    pub edition: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInformation {
    pub id: String,
    pub tasks: Vec<ProofRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: String,
    /// The current active task this instance wants to obtain or is working on.
    pub task: Option<ProofRequestOptions>,
    /// `true` if this instance started working on `task`
    pub obtained: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub block_gas_limit: usize,
    pub max_txs: usize,
    pub max_calldata: usize,
    pub max_bytecode: usize,
    pub min_k: usize,
    pub pad_to: usize,
    pub min_k_aggregation: usize,
}

fn default_bool() -> bool {
    false
}
