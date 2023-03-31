mod common;

use crate::common::get_shared_state;
use crate::common::zkevm_abi;
use coordinator::shared_state::SharedState;
use coordinator::structs::BlockHeader;
use coordinator::structs::MerkleProofRequest;
use coordinator::structs::MessageBeacon;
use coordinator::utils::*;
use ethers_core::abi::RawLog;
use ethers_core::abi::Tokenizable;
use ethers_core::types::Address;
use ethers_core::types::Bytes;
use ethers_core::types::Filter;
use ethers_core::types::Log;
use ethers_core::types::TransactionReceipt;
use ethers_core::types::ValueOrArray;
use ethers_core::types::H256;
use ethers_core::types::U256;
use ethers_signers::Signer;

async fn trigger_l1_block_import(shared_state: &SharedState) {
    let abi = zkevm_abi();
    let nonce: U256 = rand::random::<usize>().into();
    let calldata = abi
        .function("dispatchMessage")
        .unwrap()
        .encode_input(&[
            Address::zero().into_token(),
            U256::zero().into_token(),
            U256::MAX.into_token(),
            nonce.into_token(),
            Bytes::from([]).into_token(),
        ])
        .unwrap();
    let l1_bridge_addr = shared_state.config.lock().await.l1_bridge;
    shared_state
        .transaction_to_l1(Some(l1_bridge_addr), U256::zero(), calldata)
        .await
        .expect("dispatchMessage");
    shared_state.sync().await;
    shared_state.mine().await;
    finalize_chain!(shared_state, true);
}

async fn trigger_l2_block_import(shared_state: &SharedState) {
    let abi = zkevm_abi();
    let nonce: U256 = rand::random::<usize>().into();
    let calldata = abi
        .function("dispatchMessage")
        .unwrap()
        .encode_input(&[
            Address::zero().into_token(),
            U256::zero().into_token(),
            U256::MAX.into_token(),
            nonce.into_token(),
            Bytes::from([]).into_token(),
        ])
        .unwrap();
    let l2_bridge_addr = shared_state.ro.l2_message_dispatcher_addr;
    shared_state
        .transaction_to_l2(Some(l2_bridge_addr), U256::zero(), calldata, None)
        .await
        .expect("dispatchMessage");
    shared_state.sync().await;
    shared_state.mine().await;
    finalize_chain!(shared_state, true);
}

async fn drop_message_l1(
    shared_state: &SharedState,
    msg: &MessageBeacon,
    proof_bytes: Option<Bytes>,
) -> Result<TransactionReceipt, String> {
    let l1_bridge_addr = shared_state.config.lock().await.l1_bridge;
    let l2_bridge_addr = shared_state.ro.l2_message_dispatcher_addr;
    let abi = zkevm_abi();
    let mut account_proof = Bytes::from([]);
    let block_hash = shared_state
        .rw
        .lock()
        .await
        .chain_state
        .finalized_block_hash;
    let proof = match proof_bytes {
        Some(value) => value,
        None => {
            let storage_slot = msg.storage_slot();
            let proof_obj: MerkleProofRequest = shared_state
                .request_l2("eth_getProof", (l2_bridge_addr, [storage_slot], block_hash))
                .await
                .expect("eth_getProof");
            let proof: Bytes = Bytes::from(marshal_proof_single(&proof_obj.storage_proof[0].proof));
            account_proof = Bytes::from(marshal_proof_single(&proof_obj.account_proof));

            proof
        }
    };

    let mut tmp = vec![0u8; 32];
    let mut bytes = abi
        .function("multicall")
        .unwrap()
        .encode_input(&[])
        .unwrap();
    // import block header
    {
        let l2_block_num: u64 = {
            let block: BlockHeader = shared_state
                .request_l2("eth_getHeaderByHash", [block_hash])
                .await
                .expect("block");
            block.number.as_u64()
        };
        assert!(l2_block_num != 0);
        let block_data: Bytes = shared_state
            .request_l2("debug_getHeaderRlp", [l2_block_num])
            .await
            .expect("block_data");
        let calldata = abi
            .function("importForeignBridgeState")
            .unwrap()
            .encode_input(&[block_data.into_token(), account_proof.into_token()])
            .unwrap();
        U256::from(calldata.len()).to_big_endian(&mut tmp);
        bytes.extend(&tmp[28..32]);
        bytes.extend(calldata);
    }
    // drop message
    {
        let calldata = abi
            .function("dropMessage")
            .unwrap()
            .encode_input(&[
                msg.from.into_token(),
                msg.to.into_token(),
                msg.value.into_token(),
                msg.fee.into_token(),
                msg.deadline.into_token(),
                msg.nonce.into_token(),
                Bytes::from(msg.calldata.clone()).into_token(),
                proof.clone().into_token(),
            ])
            .expect("calldata");
        U256::from(calldata.len()).to_big_endian(&mut tmp);
        bytes.extend(&tmp[28..32]);
        bytes.extend(calldata);
    }

    shared_state
        .transaction_to_l1(Some(l1_bridge_addr), U256::zero(), bytes)
        .await
}

async fn drop_message_l2(
    shared_state: &SharedState,
    msg: &MessageBeacon,
    proof_bytes: Option<Bytes>,
) -> Result<H256, String> {
    let l1_bridge_addr = shared_state.config.lock().await.l1_bridge;
    let l2_bridge_addr = shared_state.ro.l2_message_dispatcher_addr;
    let abi = zkevm_abi();
    let proof = match proof_bytes {
        Some(value) => value,
        None => {
            let block_hash: H256 = {
                let l2_block_num: u64 = {
                    let block: BlockHeader = shared_state
                        .request_l2("eth_getHeaderByNumber", ["latest"])
                        .await
                        .expect("block");
                    block.number.as_u64()
                };
                assert!(l2_block_num != 0);
                let from_block = {
                    if l2_block_num > 100 {
                        l2_block_num - 100
                    } else {
                        1
                    }
                };
                let evt = abi.event("ForeignBridgeStateImported").unwrap();
                let filter = Filter::new()
                    .from_block(from_block)
                    .to_block(l2_block_num)
                    .address(ValueOrArray::Value(
                        shared_state.ro.l2_message_deliverer_addr,
                    ))
                    .topic0(ValueOrArray::Array(vec![evt.signature()]));

                let logs: Vec<Log> = shared_state
                    .request_l2("eth_getLogs", [&filter])
                    .await
                    .expect("eth_getLogs");

                assert!(!logs.is_empty());
                let log = logs.last().unwrap();
                let evt = evt
                    .parse_log(RawLog::from((log.topics.to_owned(), log.data.to_vec())))
                    .unwrap();

                H256::from_token(evt.params[0].value.to_owned()).unwrap()
            };
            let storage_slot = msg.storage_slot();
            let proof_obj: MerkleProofRequest = shared_state
                .request_l1("eth_getProof", (l1_bridge_addr, [storage_slot], block_hash))
                .await
                .expect("eth_getProof");
            let proof: Bytes = Bytes::from(marshal_proof_single(&proof_obj.storage_proof[0].proof));

            proof
        }
    };
    let calldata = abi
        .function("dropMessage")
        .unwrap()
        .encode_input(&[
            msg.from.into_token(),
            msg.to.into_token(),
            msg.value.into_token(),
            msg.fee.into_token(),
            msg.deadline.into_token(),
            msg.nonce.into_token(),
            Bytes::from(msg.calldata.clone()).into_token(),
            proof.clone().into_token(),
        ])
        .unwrap();
    shared_state
        .transaction_to_l2(Some(l2_bridge_addr), U256::zero(), calldata, None)
        .await
}

fn gen_l1_message(shared_state: &SharedState) -> MessageBeacon {
    let from = shared_state.ro.l1_wallet.address();
    let to = Address::zero();
    let value = U256::from(1u64);
    let fee = U256::zero();
    let deadline = U256::from(1);
    let nonce: U256 = rand::random::<usize>().into();
    let data = Bytes::from((0..42).map(|_| rand::random::<u8>()).collect::<Vec<u8>>());

    let mut msg = MessageBeacon {
        id: H256::zero(),
        from,
        to,
        value,
        fee,
        deadline,
        nonce,
        calldata: data.to_vec(),
    };
    msg.id = msg.gen_id();

    msg
}

fn gen_l2_message(shared_state: &SharedState) -> MessageBeacon {
    let from = shared_state.ro.l2_wallet.address();
    let to = Address::zero();
    let value = U256::from(1u64);
    let fee = U256::zero();
    let deadline = U256::from(1);
    let nonce: U256 = rand::random::<usize>().into();
    let data = Bytes::from((0..42).map(|_| rand::random::<u8>()).collect::<Vec<u8>>());

    let mut msg = MessageBeacon {
        id: H256::zero(),
        from,
        to,
        value,
        fee,
        deadline,
        nonce,
        calldata: data.to_vec(),
    };
    msg.id = msg.gen_id();

    msg
}

async fn dispatch_msg_l1(
    shared_state: &SharedState,
    msg: &MessageBeacon,
) -> Result<TransactionReceipt, String> {
    let abi = zkevm_abi();
    let calldata = abi
        .function("dispatchMessage")
        .unwrap()
        .encode_input(&[
            msg.to.into_token(),
            msg.fee.into_token(),
            msg.deadline.into_token(),
            msg.nonce.into_token(),
            Bytes::from(msg.calldata.clone()).into_token(),
        ])
        .expect("dispatchMessage");
    let l1_bridge_addr = Some(shared_state.config.lock().await.l1_bridge);
    shared_state
        .transaction_to_l1(l1_bridge_addr, msg.value + msg.fee, calldata)
        .await
}

async fn dispatch_msg_l2(shared_state: &SharedState, msg: &MessageBeacon) -> Result<H256, String> {
    let abi = zkevm_abi();
    let calldata = abi
        .function("dispatchMessage")
        .unwrap()
        .encode_input(&[
            msg.to.into_token(),
            msg.fee.into_token(),
            msg.deadline.into_token(),
            msg.nonce.into_token(),
            Bytes::from(msg.calldata.clone()).into_token(),
        ])
        .expect("dispatchMessage");
    let l2_bridge_addr = Some(shared_state.ro.l2_message_dispatcher_addr);
    shared_state
        .transaction_to_l2(l2_bridge_addr, msg.value + msg.fee, calldata, None)
        .await
}

#[tokio::test]
async fn l1_drop_message() {
    let shared_state = await_state!();
    let msg = gen_l1_message(&shared_state);

    // dispatch
    {
        dispatch_msg_l1(&shared_state, &msg)
            .await
            .expect("dispatch_message success");
        assert_eq!(
            dispatch_msg_l1(&shared_state, &msg).await.unwrap_err(),
            "execution reverted: DMH"
        );
    }

    trigger_l2_block_import(&shared_state).await;

    // drop
    {
        drop_message_l1(&shared_state, &msg, None)
            .await
            .expect("drop_message success");
        assert_eq!(
            drop_message_l1(&shared_state, &msg, None)
                .await
                .unwrap_err(),
            "execution reverted: DMH"
        );
    }

    finalize_chain!(shared_state);
}

#[tokio::test]
async fn l2_drop_message() {
    let shared_state = await_state!();
    let msg = gen_l2_message(&shared_state);

    // dispatch
    {
        shared_state.mine().await;
        dispatch_msg_l2(&shared_state, &msg)
            .await
            .expect("dispatch_message success");

        shared_state.mine().await;
        assert_eq!(
            dispatch_msg_l2(&shared_state, &msg).await.unwrap_err(),
            "execution reverted: DMH"
        );
    }

    trigger_l1_block_import(&shared_state).await;

    // drop
    {
        shared_state.mine().await;
        drop_message_l2(&shared_state, &msg, None)
            .await
            .expect("drop_message success");

        shared_state.mine().await;
        assert_eq!(
            drop_message_l2(&shared_state, &msg, None)
                .await
                .unwrap_err(),
            "execution reverted: DMH"
        );
    }

    shared_state.mine().await;
    finalize_chain!(shared_state);
}

#[tokio::test]
async fn l2_drop_message_zero_length_proof() {
    let shared_state = await_state!();
    let msg = gen_l2_message(&shared_state);

    // dispatch
    {
        shared_state.mine().await;
        dispatch_msg_l2(&shared_state, &msg)
            .await
            .expect("dispatch_message success");

        shared_state.mine().await;
        assert_eq!(
            dispatch_msg_l2(&shared_state, &msg).await.unwrap_err(),
            "execution reverted: DMH"
        );
    }

    trigger_l1_block_import(&shared_state).await;

    // drop
    {
        shared_state.mine().await;
        assert_eq!(
            drop_message_l2(&shared_state, &msg, Some(Bytes::from([])))
                .await
                .unwrap_err(),
            "execution reverted: BOUNDS"
        );
    }

    shared_state.mine().await;
    finalize_chain!(shared_state);
}

#[tokio::test]
async fn l1_drop_message_deadline_not_reached() {
    let shared_state = await_state!();
    let mut msg = gen_l1_message(&shared_state);
    msg.deadline = U256::MAX;
    msg.id = msg.gen_id();

    // dispatch
    {
        dispatch_msg_l1(&shared_state, &msg)
            .await
            .expect("dispatch_message success");
        assert_eq!(
            dispatch_msg_l1(&shared_state, &msg).await.unwrap_err(),
            "execution reverted: DMH"
        );
    }

    trigger_l2_block_import(&shared_state).await;

    // drop
    {
        assert_eq!(
            drop_message_l1(&shared_state, &msg, None)
                .await
                .unwrap_err(),
            "execution reverted: DMTS"
        );
    }

    finalize_chain!(shared_state);
}
