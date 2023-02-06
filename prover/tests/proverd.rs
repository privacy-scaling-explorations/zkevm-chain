use prover::server::serve;
use prover::shared_state::SharedState;
use tokio::time::{sleep, Duration};
use zkevm_common::prover::*;

fn init_logger() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .is_test(true)
        .try_init();
}

#[tokio::test]
#[allow(clippy::let_underscore_future)]
async fn proverd_simple_signaling() {
    init_logger();

    let node_a = SharedState::new("a".to_string(), Some("127.0.0.1:11111".to_string()));
    let node_b = SharedState::new("b".to_string(), Some("127.0.0.1:11112".to_string()));
    // start http servers
    {
        let _ = serve(&node_a, node_b.ro.node_lookup.as_ref().unwrap());
        let _ = serve(&node_b, node_a.ro.node_lookup.as_ref().unwrap());
    }

    // wait a bit for the rpc server to start
    sleep(Duration::from_millis(300)).await;

    let proof_a = ProofRequestOptions {
        circuit: "super".to_string(),
        block: 1,
        retry: false,
        rpc: "http://localhost:1111".to_string(),
        ..Default::default()
    };
    let proof_b = ProofRequestOptions {
        circuit: "super".to_string(),
        block: 2,
        retry: false,
        rpc: "http://localhost:1111".to_string(),
        ..Default::default()
    };

    // enqueue tasks
    assert!(node_a.get_or_enqueue(&proof_a).await.is_none());
    assert!(node_b.get_or_enqueue(&proof_b).await.is_none());

    // start work on node_a
    node_a.duty_cycle().await;
    assert!(node_a.get_or_enqueue(&proof_a).await.is_some());

    // node_b didn't sync yet
    assert!(node_b.get_or_enqueue(&proof_a).await.is_none());
    // sync, do work
    let _ = node_b.merge_tasks_from_peers().await;
    // check again
    assert!(node_b.get_or_enqueue(&proof_a).await.is_some());

    // no result yet
    assert!(node_b.get_or_enqueue(&proof_b).await.is_none());
    // sync, do work
    node_b.duty_cycle().await;
    // check again
    assert!(node_b.get_or_enqueue(&proof_b).await.is_some());

    // node_a didn't sync yet
    assert!(node_a.get_or_enqueue(&proof_b).await.is_none());
    // sync node_a
    let _ = node_a.merge_tasks_from_peers().await;
    // check again
    assert!(node_a.get_or_enqueue(&proof_b).await.is_some());
}
