use clap::Parser;
use ethers_core::types::Address;
use hyper::Uri;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
#[clap(version, about)]
/// zkEVM coordinator, coordinates between the prover and the block production and relays between the bridge contracts in L1 and L2.
pub struct Config {
    #[clap(long, env = "COORDINATOR_RPC_SERVER_NODES")]
    /// Addresses in the form of host:port[,host:port,...] to connect to the RPC servers.
    pub rpc_server_nodes: String,

    #[clap(long, env = "COORDINATOR_ENABLE_FAUCET")]
    /// Enables faucet to send eth to L1 wallet.
    pub enable_faucet: bool,

    #[clap(long, env = "COORDINATOR_LISTEN")]
    /// Address for the coordinator to listen to, in the format of ip:port.
    pub listen: SocketAddr,

    #[clap(long, env = "COORDINATOR_DUMMY_PROVER")]
    /// Enables dummy prover, so request will not be sent to the actuall prover.
    pub dummy_prover: bool,

    #[clap(long, env = "COORDINATOR_L1_RPC_URL")]
    /// L1 RPC node URL format.
    pub l1_rpc_url: Uri,

    #[clap(long, env = "COORDINATOR_L1_BRIDGE")]
    /// Ethereum address of the L1 bridge contract.
    pub l1_bridge: Address,

    #[clap(long, env = "COORDINATOR_L1_PRIV")]
    /// Private key for Ethereum L1 wallet.
    pub l1_priv: String,

    #[clap(long, env = "COORDINATOR_L2_RPC_URL")]
    /// L2 RPC node in http URL format.
    pub l2_rpc_url: Uri,

    #[clap(long, env = "COORDINATOR_PROVER_RPCD_URL")]
    /// Prover RPC node URL.
    pub prover_rpcd_url: Uri,

    #[clap(long, env = "COORDINATOR_PARAMS_PATH")]
    /// Parameters file to use for the prover requests.
    pub params_path: String,
}
