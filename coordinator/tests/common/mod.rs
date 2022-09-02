use coordinator::shared_state::SharedState;
use ethers_core::abi::decode;
use ethers_core::abi::ParamType;
use ethers_core::types::Bytes;
use serde::de::IntoDeserializer;
use serde::Deserialize;

fn deserialize_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
    let str = String::deserialize(deserializer).expect("String");
    let val: serde_json::Value = format!("0x{}", str).into();
    let res = Bytes::deserialize(val.into_deserializer());

    Ok(res.unwrap())
}

#[derive(Debug, serde::Deserialize)]
pub struct Trace {
    pub gas: u64,
    #[serde(rename = "returnValue", deserialize_with = "deserialize_bytes")]
    pub return_value: Bytes,
    failed: bool,
}

pub async fn l1_trace(calldata: &Bytes, shared_state: &SharedState) -> Result<Trace, String> {
    let bytecode: String =
        std::fs::read_to_string("../build/contracts/ZkEvmTest.bin-runtime").unwrap();
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
                    "code": format!("0x{}", bytecode),
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
