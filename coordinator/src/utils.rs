use hyper::body::Buf;
use hyper::client::HttpConnector;
use hyper::{Body, Request, Uri};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::structs::{JsonRpcRequest, JsonRpcResponse};
use crate::timeout;

use ethers_core::types::transaction::eip2930::AccessListWithGasUsed;
use ethers_core::types::{
    Address, Block, Bytes, Eip1559TransactionRequest, TransactionReceipt, TransactionRequest, H256,
    U256,
};
use ethers_core::utils::keccak256;
use ethers_signers::{LocalWallet, Signer};

pub async fn jsonrpc_request<T: Serialize + Send + Sync, R: DeserializeOwned>(
    uri: &Uri,
    method: &str,
    params: T,
) -> Result<R, String> {
    let client = hyper::Client::new();
    jsonrpc_request_client(&client, uri, method, params).await
}

pub async fn jsonrpc_request_client<T: Serialize + Send + Sync, R: DeserializeOwned>(
    client: &hyper::Client<HttpConnector>,
    uri: &Uri,
    method: &str,
    params: T,
) -> Result<R, String> {
    let node_req = Request::post(uri);
    let req_obj = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 0,
        method: method.to_string(),
        params,
    };

    let node_req = node_req
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_obj).unwrap()))
        .unwrap();

    let resp = client.request(node_req).await.unwrap();
    let body = hyper::body::aggregate(resp).await.unwrap();
    let json: JsonRpcResponse<R> = serde_json::from_reader(body.reader()).unwrap();

    if json.error.is_some() {
        return Err(json.error.unwrap().message);
    }

    if json.result.is_none() {
        return Err("no result in response".to_string());
    }

    Ok(json.result.unwrap())
}

/// may override any pending transactions
pub async fn send_transaction_to_l1(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    wallet: &LocalWallet,
    to: Address,
    value: U256,
    calldata: Vec<u8>,
) {
    let wallet_addr: Address = wallet.address();
    let nonce: U256 = jsonrpc_request_client(
        client,
        node_uri,
        "eth_getTransactionCount",
        (wallet_addr, "latest"),
    )
    .await
    .expect("nonce");

    let gas_price: U256 = jsonrpc_request_client(client, node_uri, "eth_gasPrice", ())
        .await
        .expect("gasPrice");

    let tx: Eip1559TransactionRequest = Eip1559TransactionRequest::new()
        .from(wallet_addr)
        .to(to)
        .nonce(nonce)
        .value(value)
        .max_priority_fee_per_gas(1u64)
        .max_fee_per_gas(gas_price * 2u64)
        .data(calldata);

    let access_list: AccessListWithGasUsed =
        jsonrpc_request_client(client, node_uri, "eth_createAccessList", [&tx])
            .await
            .expect("eth_createAccessList");
    let tx = tx.access_list(access_list.access_list);
    let estimate: U256 = jsonrpc_request_client(client, node_uri, "eth_estimateGas", [&tx])
        .await
        .expect("eth_estimateGas");
    let tx = tx.gas(estimate).into();

    log::debug!("sending l1 tx: {:?}", tx);

    let sig = wallet
        .sign_transaction(&tx)
        .await
        .expect("sign_transaction");
    let raw_tx = tx.rlp_signed(wallet.chain_id(), &sig);

    // wait up to 120 seconds
    let _ = timeout!(120_000, wait_for_tx(client, node_uri, &raw_tx).await);
}

/// may override any pending transactions
pub async fn send_transaction_to_l2(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    wallet: &LocalWallet,
    to: Address,
    value: U256,
    calldata: Vec<u8>,
) {
    let wallet_addr: Address = wallet.address();
    let nonce: U256 = jsonrpc_request_client(
        client,
        node_uri,
        "eth_getTransactionCount",
        (wallet_addr, "latest"),
    )
    .await
    .expect("nonce");

    let gas_price: U256 = jsonrpc_request_client(client, node_uri, "eth_gasPrice", ())
        .await
        .expect("gasPrice");

    let tx = TransactionRequest::new()
        .from(wallet_addr)
        .to(to)
        .nonce(nonce)
        .value(value)
        .gas_price(gas_price * 2u64)
        .data(calldata);

    let estimate: U256 = jsonrpc_request_client(client, node_uri, "eth_estimateGas", [&tx])
        .await
        .expect("estimateGas");
    let tx = tx.gas(estimate).into();

    let sig = wallet.sign_transaction(&tx).await.unwrap();
    let raw_tx = tx.rlp_signed(wallet.chain_id(), &sig);

    // TODO: will be obsolete once execution api is used
    let resp: Result<serde_json::Value, String> =
        jsonrpc_request_client(client, node_uri, "eth_sendRawTransaction", [raw_tx]).await;

    match resp {
        Err(err) => {
            println!("err {:?}", err);
        }
        Ok(res) => {
            println!("ok {:?}", res);
        }
    }
}

/// Can loop forever, thus should be wrapped inside timeout handler
pub async fn wait_for_tx(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    raw_tx: &Bytes,
) -> Result<TransactionReceipt, String> {
    let tx_hash = H256::from_slice(&keccak256(&raw_tx));

    // ignore
    let resp: Result<H256, String> =
        jsonrpc_request_client(client, node_uri, "eth_sendRawTransaction", [raw_tx]).await;

    log::debug!("{:?}", resp);

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let receipt: Result<TransactionReceipt, String> =
            jsonrpc_request_client(client, node_uri, "eth_getTransactionReceipt", [&tx_hash]).await;

        log::debug!("{:?}", receipt);

        if receipt.is_err() {
            continue;
        }

        let receipt = receipt.expect("TransactionReceipt");

        if receipt.status.expect("tx.status").as_u64() != 1 {
            return Err("transaction reverted".to_string());
        }

        return Ok(receipt);
    }
}

pub fn format_block(block: &Block<H256>) -> String {
    format!(
        "Block {}({}) {} txs",
        block.number.unwrap(),
        block.hash.unwrap(),
        block.transactions.len()
    )
}

pub async fn get_chain_head_hash(client: &hyper::Client<HttpConnector>, uri: &Uri) -> H256 {
    #[derive(serde::Deserialize)]
    struct BlockHeader {
        hash: H256,
    }

    let block: BlockHeader = timeout!(
        5000,
        jsonrpc_request_client(client, uri, "eth_getHeaderByNumber", ["latest"])
            .await
            .unwrap()
    );

    block.hash
}

pub async fn get_blocks_between(
    client: &hyper::Client<HttpConnector>,
    uri: &Uri,
    from: &H256,
    to: &H256,
) -> Vec<Block<H256>> {
    let mut ret: Vec<Block<H256>> = Vec::new();
    let mut hash = *to;
    loop {
        let block: Block<H256> = timeout!(
            5000,
            jsonrpc_request_client(client, uri, "eth_getBlockByHash", (hash, false))
                .await
                .expect("eth_getBlockByHash")
        );
        hash = block.parent_hash;

        if block.hash.unwrap() != *from {
            ret.push(block);
        }
        if hash == *from {
            break;
        }
    }

    ret
}
