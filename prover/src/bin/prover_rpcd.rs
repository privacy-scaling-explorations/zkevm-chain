use clap::Parser;
use env_logger::Env;

use prover::server::serve;
use prover::shared_state::SharedState;
use prover::VERSION;

#[derive(Parser, Debug)]
#[clap(version = VERSION, about)]
/// This command starts a http/json-rpc server and serves proof oriented methods.
pub(crate) struct ProverdConfig {
    #[clap(long, env = "PROVERD_BIND")]
    /// The interface address + port combination to accept connections on,
    /// e.g. `[::]:1234`.
    bind: String,
    #[clap(long, env = "PROVERD_LOOKUP")]
    /// A `HOSTNAME:PORT` conformant string that will be used for DNS service discovery of other nodes.
    lookup: Option<String>,
}

#[tokio::main]
async fn main() {
    let config = ProverdConfig::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let shared_state = SharedState::new(SharedState::random_worker_id(), config.lookup);
    {
        // start the http server
        let h1 = serve(&shared_state, &config.bind);

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
