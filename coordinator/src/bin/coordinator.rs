use std::collections::HashMap;
use std::env::var;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use env_logger::Env;
use ethers_core::types::{Address, Block, TxpoolStatus, H256, U64};

use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};

use hyper::body::{Buf, HttpBody};
use hyper::client::HttpConnector;
use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::HeaderMap;
use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri};

use serde::de::DeserializeOwned;
use serde::Serialize;

const EVENT_LOOP_COOLDOWN: Duration = Duration::from_millis(3000);
const WRAPPER_MACRO_TIMEOUT: Duration = Duration::from_millis(5000);
// Only for testing
const MAX_PENDING_PROOFS: u32 = 1;
/// allowed jsonrpc methods
const PROXY_ALLOWED_METHODS: [&str; 40] = [
    "eth_chainId",
    "eth_gasPrice",
    "eth_blockNumber",
    "eth_estimateGas",
    "eth_call",
    "eth_getCode",
    "eth_createAccessList",
    "eth_feeHistory",
    "eth_getLogs",
    "eth_getBalance",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_sendRawTransaction",
    "eth_getTransactionReceipt",
    "eth_getTransactionByHash",
    "net_version",
    "web3_clientVersion",
    "eth_getHeaderByNumber",
    "eth_getHeaderByHash",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getRawTransactionByHash",
    "eth_getProof",
    "debug_accountRange",
    "debug_getHeaderRlp",
    "debug_getBlockRlp",
    "debug_dumpBlock",
    "debug_traceBlock",
    "debug_intermediateRoots",
    "debug_traceBlockByNumber",
    "debug_traceBlockByHash",
    "debug_traceTransaction",
    "debug_traceCall",
    "debug_storageRangeAt",
    "debug_getModifiedAccountsByNumber",
    "debug_getModifiedAccountsByHash",
];

/// Wraps a expression inside an async block that timeouts after `WRAPPER_MACRO_TIMEOUT`
macro_rules! timeout {
    ($l:expr) => {
        async {
            let res = timeout(WRAPPER_MACRO_TIMEOUT, async { $l }).await;

            if let Err(err) = &res {
                log::error!("timeout: {}", err);
            }
            res
        }
        .await
        .unwrap()
    };
}

#[derive(serde::Deserialize, serde::Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct JsonRpcResponseError {
    jsonrpc: String,
    id: u64,
    error: JsonRpcError,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JsonRpcRequest<T: Serialize> {
    jsonrpc: String,
    id: u64,
    method: String,
    params: T,
}

#[derive(serde::Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ForkchoiceStateV1 {
    #[serde(rename = "headBlockHash")]
    head_block_hash: H256,
    #[serde(rename = "safeBlockHash")]
    safe_block_hash: H256,
    #[serde(rename = "finalizedBlockHash")]
    finalized_block_hash: H256,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PayloadAttributesV1 {
    timestamp: U64,
    random: H256,
    #[serde(rename = "suggestedFeeRecipient")]
    suggested_fee_recipient: Address,
}

struct SharedState {
    chain_state: ForkchoiceStateV1,
    leader_node: Uri,
    nodes: Vec<Uri>,
    prover_requests: HashMap<U64, Option<String>>,
    pending_proofs: u32,
}

fn set_headers(headers: &mut HeaderMap, extended: bool) {
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));

    if extended {
        headers.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("post, get, options"),
        );
        headers.insert(
            "access-control-allow-headers",
            HeaderValue::from_static("origin, content-type, accept, x-requested-with"),
        );
        headers.insert("access-control-max-age", HeaderValue::from_static("300"));
    }
}

async fn handle_request(
    shared_state: Arc<Mutex<SharedState>>,
    client: hyper::Client<HttpConnector>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    // TODO: support deflate content encoding

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ProxyRequest {
        id: u64,
        method: String,
    }

    {
        // limits the request size
        const MAX_BODY_SIZE: u64 = 4 << 20;
        let response_content_length = match req.body().size_hint().upper() {
            Some(v) => v,
            None => MAX_BODY_SIZE + 1,
        };

        if response_content_length > MAX_BODY_SIZE {
            let mut resp = Response::new(Body::from("request too large"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    }

    match (req.method(), req.uri().path()) {
        // serve some information about the chain
        (&Method::GET, "/") => {
            let mut resp = Response::new(Body::from(
                serde_json::to_vec(&shared_state.lock().await.chain_state).unwrap(),
            ));
            set_headers(resp.headers_mut(), false);
            Ok(resp)
        }

        // json-rpc
        (&Method::POST, "/") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let obj: ProxyRequest = serde_json::from_slice(body_bytes.as_ref()).unwrap();

            // only allow allow the following methods and nothing else
            if !PROXY_ALLOWED_METHODS.iter().any(|e| **e == obj.method) {
                let err = JsonRpcResponseError {
                    jsonrpc: "2.0".to_string(),
                    id: obj.id,
                    error: JsonRpcError {
                        code: -32601,
                        message: "this method is not available".to_string(),
                    },
                };
                let resp = Response::new(Body::from(serde_json::to_vec(&err).unwrap()));
                return Ok(resp);
            }

            let mut resp;
            {
                // choose a serving node or none
                let r = rand::random::<usize>();
                let ctx = shared_state.lock().await;
                let len = ctx.nodes.len();
                if len == 0 {
                    drop(ctx);
                    resp = Response::default();
                    *resp.status_mut() = StatusCode::SERVICE_UNAVAILABLE
                } else {
                    let node_req = Request::post(&ctx.nodes[r % len]);
                    drop(ctx);
                    // reusing the same request doesn't work correctly.
                    // Feeding the body via a reader() which was already consumed doesn't work either :/
                    let node_req = node_req
                        .header(hyper::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body_bytes))
                        .unwrap();
                    resp = client.request(node_req).await.unwrap();
                }
            }

            set_headers(resp.headers_mut(), false);
            Ok(resp)
        }

        // serve CORS headers
        (&Method::OPTIONS, "/") => {
            let mut resp = Response::default();
            set_headers(resp.headers_mut(), true);
            Ok(resp)
        }

        // everything else
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

impl SharedState {
    fn new(leader_url: &str) -> SharedState {
        Self {
            chain_state: ForkchoiceStateV1 {
                head_block_hash: H256::zero(),
                safe_block_hash: H256::zero(),
                finalized_block_hash: H256::zero(),
            },
            leader_node: Uri::try_from(leader_url).unwrap(),
            nodes: Vec::new(),
            prover_requests: HashMap::new(),
            pending_proofs: 0,
        }
    }

    async fn init(&mut self) {
        if !self.chain_state.head_block_hash.is_zero() {
            panic!("init");
        }

        let genesis: Block<H256> =
            timeout!(
                jsonrpc_request(&self.leader_node, "eth_getBlockByNumber", ("0x0", false))
                    .await
                    .unwrap()
            );
        let h = genesis.hash.unwrap();
        log::info!("init with genesis: {:?}", h);

        self.chain_state.head_block_hash = h;
        self.chain_state.safe_block_hash = h;
        self.chain_state.finalized_block_hash = h;
    }
}

async fn get_chain_head_hash(uri: &Uri) -> H256 {
    #[derive(serde::Deserialize)]
    struct BlockHeader {
        hash: H256,
    }

    let block: BlockHeader = timeout!(jsonrpc_request(uri, "eth_getHeaderByNumber", ["latest"])
        .await
        .unwrap());

    block.hash
}

async fn get_blocks_between(
    client: &hyper::Client<HttpConnector>,
    uri: &Uri,
    from: &H256,
    to: &H256,
) -> Vec<Block<H256>> {
    let mut ret: Vec<Block<H256>> = Vec::new();
    let mut hash = *to;
    loop {
        let block: Block<H256> =
            timeout!(
                jsonrpc_request_client(client, uri, "eth_getBlockByHash", (hash, false))
                    .await
                    .unwrap()
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

fn format_block(block: &Block<H256>) -> String {
    format!(
        "Block {}({}) {} txs",
        block.number.unwrap(),
        block.hash.unwrap(),
        block.transactions.len()
    )
}

async fn jsonrpc_request<T: Serialize + Send + Sync, R: DeserializeOwned>(
    uri: &Uri,
    method: &str,
    params: T,
) -> Result<R, String> {
    let client = hyper::Client::new();
    jsonrpc_request_client(&client, uri, method, params).await
}

async fn jsonrpc_request_client<T: Serialize + Send + Sync, R: DeserializeOwned>(
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

async fn event_loop(state_ref: Arc<Mutex<SharedState>>, client: hyper::Client<HttpConnector>) {
    // TODO: get rid of most locks
    // update available server instances
    // choose leader
    // verify chainhead
    // seal a block
    // submit blocks - if any
    // check if a block can be finalized

    let mut ctx = state_ref.lock().await;
    let leader_node_uri = ctx.leader_node.clone();
    // this would be normally loaded from the L1 bridge
    let head_hash = get_chain_head_hash(&leader_node_uri).await;
    let safe_hash = ctx.chain_state.safe_block_hash;
    ctx.chain_state.head_block_hash = head_hash;
    drop(ctx);

    {
        // discover & update nodes
        let addrs_iter = var("RPC_SERVER_NODES")
            .expect("RPC_SERVER_NODES env var")
            .to_socket_addrs()
            .unwrap();
        let mut nodes = Vec::new();

        for addr in addrs_iter {
            let uri = Uri::try_from(format!("http://{}", addr)).unwrap();
            let hash = get_chain_head_hash(&uri).await;
            if hash != head_hash {
                log::warn!("skipping inconsistent node: {}", uri);
                continue;
            }

            nodes.push(uri);
        }
        log::info!("found {} ready rpc nodes", nodes.len());

        // update nodes[]
        let mut ctx = state_ref.lock().await;
        ctx.nodes = nodes;
        drop(ctx);
    }

    {
        // check if we can mine a block
        let resp: TxpoolStatus =
            timeout!(
                jsonrpc_request_client(&client, &leader_node_uri, "txpool_status", ())
                    .await
                    .unwrap()
            );
        let pending_txs = resp.pending.as_u64();

        if pending_txs > 0 {
            log::info!(
                "submitting mining request to leader node - pending: {}",
                pending_txs
            );

            // kick miner
            let _resp: Option<bool> =
                timeout!(
                    jsonrpc_request_client(&client, &leader_node_uri, "miner_start", [1])
                        .await
                        .unwrap_or_default()
                );
        }
        // stop again
        let _resp: Option<bool> =
            timeout!(
                jsonrpc_request_client(&client, &leader_node_uri, "miner_stop", ())
                    .await
                    .unwrap_or_default()
            );
    }

    {
        // block submission
        if safe_hash != head_hash {
            // find all the blocks since `safe_hash`
            let blocks =
                get_blocks_between(&client, &leader_node_uri, &safe_hash, &head_hash).await;

            log::info!("blocks to be submitted: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                log::info!("TODO submit_block: {}", format_block(block));
                {
                    let mut ctx = state_ref.lock().await;
                    ctx.chain_state.safe_block_hash = block.hash.unwrap();
                    drop(ctx);
                }
            }
        }
    }

    {
        // block finalization
        let ctx = state_ref.lock().await;
        let safe_hash = ctx.chain_state.safe_block_hash;
        let final_hash = ctx.chain_state.finalized_block_hash;
        drop(ctx);
        if final_hash != safe_hash {
            let blocks =
                get_blocks_between(&client, &leader_node_uri, &final_hash, &safe_hash).await;

            log::info!("blocks for finalization: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                finalize_block(state_ref.clone(), block).await;
            }
        }
    }
}

async fn request_proof(block_num: U64) -> Result<String, String> {
    // TODO: this should be invoked via rpc without waiting for the proof to be computed
    let output = Command::new("./prover_cmd")
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env("BLOCK_NUM", block_num.to_string())
        .output();
    let output = output.await.expect("proof");

    match output.status.success() {
        false => {
            log::error!("computing proof for {}", block_num);
            Err("poof".to_string())
        }
        true => {
            let proof = String::from_utf8(output.stdout).unwrap();
            log::debug!("proof for: {} data: {}", block_num, proof);
            Ok(proof)
        }
    }
}

async fn finalize_block(shared_state: Arc<Mutex<SharedState>>, block: &Block<H256>) {
    log::debug!("TODO finalize_block: {}", format_block(block));

    let mut ctx = shared_state.lock().await;
    let k = block.number.unwrap();
    let v = ctx.prover_requests.get(&k);

    match v {
        None => {
            if ctx.pending_proofs >= MAX_PENDING_PROOFS {
                log::debug!("waiting MAX_PENDING_PROOFS");
                return;
            }
            ctx.prover_requests.insert(k, Option::default());
            ctx.pending_proofs += 1;
            drop(ctx);

            let shared_state = shared_state.clone();
            spawn(async move {
                // NOTE: if this panics then this loops forever - not a problem once switched to
                // prover rpc
                let res = request_proof(k).await;
                let mut ctx = shared_state.lock().await;
                ctx.pending_proofs -= 1;
                match res {
                    Err(_) => ctx.prover_requests.remove(&k),
                    Ok(proof) => ctx.prover_requests.insert(k, Option::Some(proof)),
                }
            });
        }
        Some(opt) => match opt {
            None => log::info!("proof not yet computed for: {}", k),
            Some(proof) => {
                log::info!("found proof: {}", proof);
                ctx.chain_state.finalized_block_hash = block.hash.unwrap();
            }
        },
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let url: String = var("RPC_URL").expect("RPC_URL env var").parse().unwrap();

    let mut shared_state: SharedState = SharedState::new(&url);
    shared_state.init().await;

    // create a reference for the global state
    let state_ref = Arc::new(Mutex::new(shared_state));

    {
        let addr = var("LISTEN")
            .expect("LISTEN env var")
            .parse::<std::net::SocketAddr>()
            .expect("valid socket address");
        let client = hyper::Client::new();
        let state_ref = state_ref.clone();
        // start the http server
        spawn(async move {
            let service = make_service_fn(move |_| {
                let state_ref = state_ref.clone();
                let client = client.clone();
                let service = service_fn(move |req| {
                    handle_request(state_ref.clone(), client.to_owned(), req)
                });

                async move { Ok::<_, hyper::Error>(service) }
            });
            let server = Server::bind(&addr).serve(service);
            log::info!("Listening on http://{}", addr);
            server.await.expect("server should be serving");
            // terminate process?
        });
    }

    let client = hyper::Client::new();
    // start the event loop
    loop {
        log::debug!("spawning event_loop task");
        let res = spawn(event_loop(state_ref.clone(), client.to_owned())).await;

        if let Err(err) = res {
            log::error!("task: {}", err);
        }

        sleep(EVENT_LOOP_COOLDOWN).await;
    }
}
