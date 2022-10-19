#![allow(dead_code)]
use coordinator::shared_state::SharedState;
use ethers_core::abi::decode;
use ethers_core::abi::AbiParser;
use ethers_core::abi::ParamType;
use ethers_core::types::Bytes;
use serde::de::IntoDeserializer;
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use tokio::sync::Mutex;
use tokio::sync::OnceCell;

fn deserialize_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
    let str = String::deserialize(deserializer).expect("String");
    let val: serde_json::Value = format!("0x{}", str).into();
    let res = Bytes::deserialize(val.into_deserializer());

    Ok(res.unwrap())
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ContractArtifact {
    #[serde(rename = "bin-runtime", deserialize_with = "deserialize_bytes")]
    pub bin_runtime: Bytes,
    pub bin: Bytes,
}

#[derive(Debug, serde::Deserialize)]
pub struct Trace {
    pub gas: u64,
    #[serde(rename = "returnValue", deserialize_with = "deserialize_bytes")]
    pub return_value: Bytes,
    pub failed: bool,
}

impl ContractArtifact {
    pub fn load(name: &str) -> Self {
        let path = format!("../build/contracts/{}.json", name);
        let file = File::open(&path).unwrap_or_else(|err| panic!("{}: {}", &path, err));
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).unwrap()
    }

    pub async fn l1_trace(
        &self,
        calldata: &Bytes,
        shared_state: &SharedState,
    ) -> Result<Trace, String> {
        let req = serde_json::json!([
            {
                "to": "0x00000000000000000000000000000000000f0000",
                "data": calldata,
            },
            "latest",
            {
                "Limit": 1,
                "stateOverrides": {
                    "0x00000000000000000000000000000000000f0000": {
                        "code": self.bin_runtime,
                    },
                },
            },
        ]);
        let trace: serde_json::Value = shared_state
            .request_l1("debug_traceCall", &req)
            .await
            .expect("debug_traceCall");
        let trace: Trace = serde_json::from_value(trace).unwrap();
        if trace.failed {
            let revert_reason = decode(&[ParamType::String], &trace.return_value.as_ref()[4..]);
            if revert_reason.is_ok() {
                return Err(format!("{:?}", revert_reason));
            }

            return Err("execution reverted".to_string());
        }

        Ok(trace)
    }
}

pub fn proxy_abi() -> ethers_core::abi::Contract {
    AbiParser::default()
        .parse(&["function upgrade(address to) external"])
        .unwrap()
}

pub fn zkevm_abi() -> ethers_core::abi::Contract {
    AbiParser::default()
        .parse(&[
            // zkevm native bridge
            "function dispatchMessage(address to, uint256 fee, uint256 deadline, uint256 nonce, bytes calldata _data) external payable",
        ])
        .expect("parse abi")
}

static ONCE: OnceCell<Mutex<SharedState>> = OnceCell::const_new();

pub async fn get_shared_state() -> &'static Mutex<SharedState> {
    ONCE.get_or_init(|| async {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .is_test(true)
                .try_init();
        let shared_state = SharedState::from_env().await;
        shared_state.init().await;

        Mutex::new(shared_state)
    })
    .await
}

#[macro_export]
macro_rules! await_state {
    () => {{
        get_shared_state().await.lock().await
    }};
}

#[macro_export]
macro_rules! sync {
    ($shared_state:expr) => {
        // sync bridge and process events
        $shared_state.sync().await;
        while $shared_state.rw.lock().await.l1_message_queue.len() > 0 {
            $shared_state.mine().await;
            $shared_state.sync().await;
        }
    };
}

#[macro_export]
macro_rules! wait_for_tx {
    ($tx_hash:expr, $url:expr) => {{
        let mut resp: Option<TransactionReceipt> = None;

        while (resp.is_none()) {
            resp = match jsonrpc_request($url, "eth_getTransactionReceipt", [$tx_hash]).await {
                Ok(val) => Some(val),
                Err(_) => None,
            };
        }

        let receipt = resp.unwrap();
        if receipt.status.unwrap() != U64::from(1) {
            panic!("transaction reverted");
        }

        receipt
    }};
}

#[macro_export]
macro_rules! finalize_chain {
    ($shared_state:expr) => {
        loop {
            let rw = $shared_state.rw.lock().await;
            if rw.chain_state.head_block_hash == rw.chain_state.finalized_block_hash {
                break;
            }
            drop(rw);

            sync!($shared_state);
            $shared_state.submit_blocks().await;
            $shared_state
                .finalize_blocks()
                .await
                .expect("finalize_blocks");
            sync!($shared_state);
            while $shared_state.rw.lock().await.l2_message_queue.len() != 0 {
                $shared_state.relay_to_l1().await;
                sync!($shared_state);
            }
        }
    };
}

#[macro_export]
macro_rules! sleep {
    ($ms:expr) => {{
        use tokio::time::{sleep, Duration};
        sleep(Duration::from_millis($ms)).await;
    }};
}
