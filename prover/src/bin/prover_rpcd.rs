use env_logger::Env;
use clap::{Parser};

use prover::server::serve;
use prover::shared_state::SharedState;

#[derive(Parser, Debug)]
pub(crate) struct ProverdConfig {
    #[clap(env = "PROVERD_BIND")]
    bind: Option<String>,
    #[clap(env = "PROVERD_LOOKUP")]
    lookup: Option<String>,
}

/// This command starts a http/json-rpc server and serves proof oriented
/// methods. Required environment variables:
/// - PROVERD_BIND
///   - the interface address + port combination to accept connections on
///     `[::]:1234`
/// - `PROVERD_LOOKUP`
///   - environment variable in the form of HOSTNAME:PORT
#[tokio::main]
async fn main() {
    let config = ProverdConfig::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let shared_state = SharedState::new(
        SharedState::random_worker_id(),
        Some(config.lookup.expect("PROVERD_LOOKUP env var"))
    );
    {
        // start the http server
        let h1 = serve(
            &shared_state,
            &config.bind.expect("PROVERD_BIND env var"),
        );

        // starts the duty cycle loop
        let ctx = shared_state.clone();
        // use a dedicated runtime for mixed async / heavy (blocking) compute
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let h2 = rt.spawn(async move {
            loop {
                let ctx = ctx.clone();
                // enclose this call to catch panics which may
                // occur due to network services
                let _ = tokio::spawn(async move {
                    log::debug!("task: duty_cycle");
                    ctx.duty_cycle().await;
                })
                .await;
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        });

        // this task loop makes sure to merge task results periodically
        // even if this instance is busy with proving
        let ctx = shared_state.clone();
        let h3 = tokio::spawn(async move {
            loop {
                let ctx = ctx.clone();
                // enclose this call to catch panics which may
                // occur due to network services
                let _ = tokio::spawn(async move {
                    log::debug!("task: merge_tasks_from_peers");
                    let _ = ctx.merge_tasks_from_peers().await;
                })
                .await;
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        });

        // wait for all tasks
        if tokio::try_join!(h1, h2, h3).is_err() {
            panic!("unexpected task error");
        }
    }
}
