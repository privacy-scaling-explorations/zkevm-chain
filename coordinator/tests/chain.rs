use coordinator::shared_state::SharedState;
use ethers_core::abi::AbiParser;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::U256;

fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::max())
        //.is_test(true)
        .try_init();
}

#[tokio::test]
async fn test_deposit() {
    init_logger();

    let abi = AbiParser::default()
        .parse(&[
            "function sendMessage(address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) external payable",
        ])
        .expect("parse abi");

    let shared_state = SharedState::from_env().await;
    shared_state.init().await;

    for _ in 0..9 {
        let to = Address::zero();
        let fee = U256::zero();
        let data = Bytes::from([]);
        let deadline = U256::from(0xffffffffffffffffu64);
        let nonce: U256 = rand::random::<usize>().into();
        let calldata = abi
            .function("sendMessage")
            .unwrap()
            .encode_input(&[
                to.into_token(),
                fee.into_token(),
                deadline.into_token(),
                nonce.into_token(),
                data.into_token(),
            ])
            .expect("calldata");

        shared_state
            .transaction_to_l1(shared_state.ro.l1_bridge_addr, U256::from(1), calldata)
            .await;
    }

    shared_state.sync().await;
    while shared_state.rw.lock().await.l1_message_queue.len() > 0 {
        shared_state.mine().await;
        shared_state.sync().await;
    }
    // TODO: test for l2 bridge events once implemented
}
