use env_logger::Env;
use prover::shared_state::SharedState;
use prover::structs::ProofRequestOptions;
use std::env::var;

/// This command generates and prints the proofs to stdout.
/// Required environment variables:
/// - BLOCK_NUM - the block number to generate the proof for
/// - RPC_URL - a geth http rpc that supports the debug namespace
/// - PARAMS_PATH - a path to a file generated with the gen_params tool
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let block_num: u64 = var("BLOCK_NUM")
        .expect("BLOCK_NUM env var")
        .parse()
        .expect("Cannot parse BLOCK_NUM env var");
    let rpc_url: String = var("RPC_URL")
        .expect("RPC_URL env var")
        .parse()
        .expect("Cannot parse RPC_URL env var");
    let params_path: String = var("PARAMS_PATH")
        .expect("PARAMS_PATH env var")
        .parse()
        .expect("Cannot parse PARAMS_PATH env var");

    let state = SharedState::new(String::new(), None);
    let request = ProofRequestOptions {
        block: block_num,
        rpc: rpc_url,
        retry: false,
        param: params_path,
    };

    state.get_or_enqueue(&request).await;
    state.duty_cycle().await;
    let result = state
        .get_or_enqueue(&request)
        .await
        .expect("some")
        .expect("result");

    serde_json::to_writer(std::io::stdout(), &result).expect("serialize and write");
}
