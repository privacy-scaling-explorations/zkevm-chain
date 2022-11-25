use coordinator::shared_state::SharedState;

// test for: https://github.com/privacy-scaling-explorations/zkevm-chain/issues/5
#[tokio::test]
async fn access_list_regression() {
    let shared_state = SharedState::from_env().await;
    shared_state.init().await;

    // CODESIZE
    // CODESIZE
    // SLOAD
    //
    // CODESIZE
    // CODESIZE
    // SSTORE
    //
    // RETURNDATASIZE
    // CODESIZE
    // SSTORE
    //
    // CODESIZE
    // CODESIZE
    // SLOAD
    //
    // ADDRESS
    // EXTCODESIZE
    //
    // RETURNDATASIZE
    // NOT
    // EXTCODESIZE
    //
    // CALLVALUE
    // EXTCODEHASH
    //
    // RETURNDATASIZE
    // RETURNDATASIZE
    // RETURNDATASIZE
    // RETURNDATASIZE
    // CODESIZE
    // CALLVALUE
    // GAS
    // CALL
    let req = serde_json::json!([
        {
            "data": "0x3838543838553d3855383854303b3d193b343f3d3d3d3d38345af1",
            "value": "0xfafbfc",
            "gas": "0x2faf080",
        },
        "latest",
        {
            "stateOverrides": {
                "0x0000000000000000000000000000000000000000": {
                    "balance": "0xffffffff",
                },
            },
        },
    ]);
    let l2: serde_json::Value = shared_state
        .request_l2("debug_traceCall", &req)
        .await
        .expect("should not crash");
    let l1: serde_json::Value = shared_state
        .request_l1("debug_traceCall", &req)
        .await
        .expect("should not crash");

    assert_eq!(l1, l2, "trace should be equal");
}
