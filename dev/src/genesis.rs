use eth_types::Bytes;
use serde_json::json;
use std::fs::File;
use std::io::BufReader;

pub fn patch_genesis_l2(name: &str, address: usize, bytecode: Bytes) {
    let path = "../docker/geth/templates/l2-testnet.json";
    let file = File::open(path).unwrap_or_else(|err| panic!("{}: {}", &path, err));
    let reader = BufReader::new(&file);
    let mut genesis: serde_json::Value = serde_json::from_reader(reader).unwrap();
    let addr = format!("{address:040x}");
    genesis["alloc"][addr] = json!({
        "comment": name,
        "balance": "0",
        "code": bytecode.to_string(),
    });
    serde_json::to_writer_pretty(File::create(path).unwrap(), &genesis).expect("write");
}

pub fn get_max_contract_size(gas_limit: usize) -> usize {
    let max_deploy_opcodes = (gas_limit - 32_000) / 16;
    std::cmp::max(24_576, max_deploy_opcodes)
}
