use crate::structs::*;
use crate::timeout;
use ethers_core::types::transaction::eip2930::AccessListWithGasUsed;
use ethers_core::types::Transaction;
use ethers_core::types::{
    Address, Block, Bytes, Eip1559TransactionRequest, TransactionReceipt, TransactionRequest, H256,
    U256,
};
use ethers_core::utils::keccak256;
use ethers_core::utils::rlp::RlpStream;
use ethers_signers::{LocalWallet, Signer};
use hyper::client::HttpConnector;
use hyper::Uri;
use zkevm_common::json_rpc::jsonrpc_request_client;

pub const RPC_REQUEST_TIMEOUT: u64 = 30000;

/// may override any pending transactions
pub async fn send_transaction_to_l1(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    wallet: &LocalWallet,
    to: Option<Address>,
    value: U256,
    calldata: Vec<u8>,
) -> Result<TransactionReceipt, String> {
    let nonce: U256 = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_getTransactionCount",
        (wallet.address(), "latest"),
    )
    .await
    .expect("nonce");

    let raw_tx = sign_transaction_l1(client, node_uri, wallet, to, value, calldata, nonce).await?;
    // wait up to 120 seconds
    timeout!(120_000, wait_for_tx(client, node_uri, &raw_tx).await)
}

/// may override any pending transactions
pub async fn sign_transaction_l1(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    wallet: &LocalWallet,
    to: Option<Address>,
    value: U256,
    calldata: Vec<u8>,
    nonce: U256,
) -> Result<Bytes, String> {
    let wallet_addr: Address = wallet.address();

    let gas_price: U256 =
        jsonrpc_request_client(RPC_REQUEST_TIMEOUT, client, node_uri, "eth_gasPrice", ())
            .await
            .expect("gasPrice");

    let mut tx: Eip1559TransactionRequest = Eip1559TransactionRequest::new()
        .chain_id(wallet.chain_id())
        .from(wallet_addr)
        .nonce(nonce)
        .value(value)
        .max_priority_fee_per_gas(1u64)
        .max_fee_per_gas(gas_price * 2u64)
        .data(calldata);

    if to.is_some() {
        tx = tx.to(to.unwrap());
    }

    let access_list: AccessListWithGasUsed = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_createAccessList",
        [&tx],
    )
    .await
    .expect("eth_createAccessList");
    let tx = tx.access_list(access_list.access_list);
    let estimate: U256 = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_estimateGas",
        [&tx],
    )
    .await?;
    let tx = tx.gas(estimate).into();

    log::debug!("sending l1 tx: {:?}", tx);

    let sig = wallet
        .sign_transaction(&tx)
        .await
        .expect("sign_transaction");

    Ok(tx.rlp_signed(&sig))
}

/// may override any pending transactions
pub async fn send_transaction_to_l2(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    wallet: &LocalWallet,
    to: Option<Address>,
    value: U256,
    calldata: Vec<u8>,
    gas_limit: Option<U256>,
) -> Result<H256, String> {
    let wallet_addr: Address = wallet.address();
    let nonce: U256 = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_getTransactionCount",
        (wallet_addr, "latest"),
    )
    .await
    .expect("nonce");

    let gas_price: U256 =
        jsonrpc_request_client(RPC_REQUEST_TIMEOUT, client, node_uri, "eth_gasPrice", ())
            .await
            .expect("gasPrice");

    let mut tx = TransactionRequest::new()
        .chain_id(wallet.chain_id())
        .from(wallet_addr)
        .nonce(nonce)
        .value(value)
        .gas_price(gas_price * 2u64)
        .data(calldata);

    if to.is_some() {
        tx = tx.to(to.unwrap())
    }

    let estimate: U256 = match gas_limit {
        Some(limit) => limit,
        None => {
            jsonrpc_request_client(
                RPC_REQUEST_TIMEOUT,
                client,
                node_uri,
                "eth_estimateGas",
                [&tx],
            )
            .await?
        }
    };
    let tx = tx.gas(estimate).into();

    let sig = wallet.sign_transaction(&tx).await.unwrap();
    let raw_tx = tx.rlp_signed(&sig);

    // TODO: will be obsolete once execution api is used
    jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_sendRawTransaction",
        [raw_tx],
    )
    .await
}

/// Can loop forever, thus should be wrapped inside timeout handler
pub async fn wait_for_tx(
    client: &hyper::Client<HttpConnector>,
    node_uri: &Uri,
    raw_tx: &Bytes,
) -> Result<TransactionReceipt, String> {
    let tx_hash = H256::from_slice(&keccak256(raw_tx));

    // ignore
    let resp: Result<H256, String> = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        node_uri,
        "eth_sendRawTransaction",
        [raw_tx],
    )
    .await;

    log::debug!("{:?}", resp);

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let receipt: Result<TransactionReceipt, String> = jsonrpc_request_client(
            RPC_REQUEST_TIMEOUT,
            client,
            node_uri,
            "eth_getTransactionReceipt",
            [&tx_hash],
        )
        .await;

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

pub fn format_block<T>(block: &Block<T>) -> String {
    format!(
        "Block {}({}) {} txs",
        block.number.unwrap(),
        block.hash.unwrap(),
        block.transactions.len()
    )
}

pub async fn get_chain_head(client: &hyper::Client<HttpConnector>, uri: &Uri) -> BlockHeader {
    let header: BlockHeader = jsonrpc_request_client(
        RPC_REQUEST_TIMEOUT,
        client,
        uri,
        "eth_getHeaderByNumber",
        ["latest"],
    )
    .await
    .unwrap();

    header
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
        let block: Block<H256> = jsonrpc_request_client(
            RPC_REQUEST_TIMEOUT,
            client,
            uri,
            "eth_getBlockByHash",
            (hash, false),
        )
        .await
        .expect("eth_getBlockByHash");
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

/// encodes the proof from `eth_getCode` suitable for the Patricia{Account,Storage}Validator contract.
pub fn marshal_proof_single(proof: &[Bytes]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    ret.extend([proof.len() as u8]);

    for b in proof.iter() {
        let data = b.as_ref();
        ret.extend(data);
    }

    ret
}

/// encodes the proof from `eth_getCode` suitable for the PatriciaValidator contract.
pub fn marshal_proof(account_proof: &[Bytes], storage_proof: &[Bytes]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    ret.extend([account_proof.len() as u8]);

    for b in account_proof.iter() {
        let data = b.as_ref();
        ret.extend(data);
    }

    ret.extend([storage_proof.len() as u8]);

    for b in storage_proof.iter() {
        let data = b.as_ref();
        ret.extend(data);
    }

    ret
}

/// Generates a witness suitable for the L1 Verifier contract(s) for block `block_num`.
pub fn encode_verifier_witness(
    block: &Block<Transaction>,
    history_hashes: &[H256],
    chain_id: &u64,
) -> Result<Vec<u8>, String> {
    fn store_word_bytes(buf: &mut Vec<u8>, val: &[u8]) {
        let mut tmp: Vec<u8> = Vec::with_capacity(32);
        tmp.resize(32 - val.len(), 0);
        tmp.extend(val);

        buf.extend(tmp);
    }

    macro_rules! store_word {
        ($a:expr, $b:expr) => {
            let mut tmp: Vec<u8> = vec![0; 32];
            $b.to_big_endian(&mut tmp);
            $a.extend(tmp);
        };
    }

    let mut witness: Vec<u8> = Vec::new();
    // block header + extra fields
    {
        let mut rlp = RlpStream::new_list(15);
        rlp.append(&block.parent_hash);
        rlp.append(&block.uncles_hash);
        rlp.append(&block.author.expect("block.author"));
        rlp.append(&block.state_root);
        rlp.append(&block.transactions_root);
        rlp.append(&block.receipts_root);
        rlp.append(&block.logs_bloom.expect("block.logs_bloom"));
        rlp.append(&block.difficulty);
        rlp.append(&block.number.expect("block.number"));
        rlp.append(&block.gas_limit);
        rlp.append(&block.gas_used);
        rlp.append(&block.timestamp);
        rlp.append(&block.extra_data.as_ref());
        rlp.append(&block.mix_hash.expect("block.mix_hash"));
        rlp.append(&block.nonce.expect("block.nonce"));
        witness.extend(rlp.out());

        for block_hash in history_hashes {
            store_word_bytes(&mut witness, block_hash.as_ref());
        }
    }

    // transactions + extra fields
    for tx in block.transactions.iter() {
        // https://eips.ethereum.org/EIPS/eip-155
        let mut rlp = RlpStream::new_list(9);
        rlp.append(&tx.nonce);
        rlp.append(&tx.gas_price.expect("gas_price"));
        rlp.append(&tx.gas);
        if tx.to.is_some() {
            rlp.append(&tx.to.unwrap().as_ref());
        } else {
            rlp.append_empty_data();
        }
        rlp.append(&tx.value);
        rlp.append(&tx.input.as_ref());
        rlp.append(chain_id);
        rlp.append_empty_data();
        rlp.append_empty_data();

        witness.extend(rlp.out());

        // extra fields
        // FIXME: can we safely encode the recovery bit of the signature into `s`?
        store_word_bytes(&mut witness, tx.from.as_ref());
        store_word!(&mut witness, &tx.r);
        store_word!(&mut witness, &tx.s);
    }

    Ok(witness)
}
