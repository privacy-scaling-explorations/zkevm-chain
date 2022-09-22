use clap::Parser;
use ethers_core::types::Address;
use hyper::Uri;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[clap(version, about)]
/// zkEVM coordinator
pub struct Config {
    #[clap(long, env = "COORDINATOR_RPC_SERVER_NODES")]
    /// COORDINATOR_RPC_SERVER_NODES
    pub rpc_server_nodes: String,

    #[clap(long, env = "COORDINATOR_ENABLE_FAUCET")]
    /// COORDINATOR_ENABLE_FAUCET
    pub enable_faucet: bool,

    #[clap(long, env = "COORDINATOR_LISTEN")]
    /// COORDINATOR_LISTEN
    pub listen: SocketAddr,

    #[clap(long, env = "COORDINATOR_DUMMY_PROVER")]
    /// COORDINATOR_DUMMY_PROVER
    pub dummy_prover: bool,

    #[clap(long, env = "COORDINATOR_L1_RPC_URL")]
    /// COORDINATOR_L1_RPC_URL
    pub l1_rpc_url: Uri,

    #[clap(long, env = "COORDINATOR_L1_BRIDGE")]
    /// COORDINATOR_L1_BRIDGE
    pub l1_bridge: Address,

    #[clap(long, env = "COORDINATOR_L1_PRIV")]
    /// COORDINATOR_L1_PRIV
    pub l1_priv: String,

    #[clap(long, env = "COORDINATOR_L2_RPC_URL")]
    /// COORDINATOR_L2_RPC_URL
    pub l2_rpc_url: Uri,

    #[clap(long, env = "COORDINATOR_PROVER_RPCD_URL")]
    /// COORDINATOR_PROVER_RPCD_URL
    pub prover_rpcd_url: Uri,

    #[clap(long, env = "COORDINATOR_PARAMS_PATH")]
    /// COORDINATOR_PARAMS_PATH
    pub params_path: String,
}
