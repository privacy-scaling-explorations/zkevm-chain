use crate::ProverParams;
use bus_mapping::circuit_input_builder::Block;
use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::rpc::GethClient;
use bus_mapping::state_db::CodeDB;
use eth_types::geth_types;
use eth_types::Word;
use eth_types::U256;
use ethers_providers::Http;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey};
use rand::rngs::OsRng;
use std::str::FromStr;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::witness;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::Curve;
use zkevm_circuits::tx_circuit::Group;
use zkevm_circuits::tx_circuit::Secp256k1Affine;
use zkevm_circuits::tx_circuit::TxCircuit;

/// Returns a instance of the `SuperCircuit`.
pub fn gen_circuit<const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    bytecode_size: usize,
    block: witness::Block<Fr>,
    txs: Vec<geth_types::Transaction>,
    keccak_inputs: Vec<Vec<u8>>,
) -> Result<SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA>, String> {
    let chain_id = block.context.chain_id;
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();
    let tx_circuit = TxCircuit::new(aux_generator, block.randomness, chain_id.as_u64(), txs);
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        block,
        fixed_table_tags: FixedTableTag::iter().collect(),
        tx_circuit,
        keccak_inputs,
        bytecode_size,
    };

    Ok(circuit)
}

// TODO: can this be pre-generated to a file?
// related
// https://github.com/zcash/halo2/issues/443
// https://github.com/zcash/halo2/issues/449
/// Compute a static proving key for SuperCircuit
pub fn gen_static_key<const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    params: &ProverParams,
    block_gas_limit: usize,
    max_bytecode: usize,
    state_circuit_pad_to: usize,
) -> Result<ProvingKey<G1Affine>, Box<dyn std::error::Error>> {
    let history_hashes = vec![Word::zero(); 256];
    let mut eth_block: eth_types::Block<eth_types::Transaction> = eth_types::Block::default();
    eth_block.number = Some(history_hashes.len().into());
    eth_block.base_fee_per_gas = Some(0.into());
    eth_block.hash = Some(eth_block.parent_hash);
    eth_block.gas_limit = block_gas_limit.into();
    let txs = eth_block
        .transactions
        .iter()
        .map(geth_types::Transaction::from)
        .collect();
    let keccak_inputs = Vec::new();

    let code_db = CodeDB::new();
    let chain_id = U256::from(99);
    let block = Block::new(chain_id, history_hashes, &eth_block)?;
    let mut block = witness::block_convert(&block, &code_db);
    block.state_circuit_pad_to = state_circuit_pad_to;

    let circuit = gen_circuit::<MAX_TXS, MAX_CALLDATA>(max_bytecode, block, txs, keccak_inputs)?;
    let vk = keygen_vk(params, &circuit)?;
    let pk = keygen_pk(params, vk, &circuit)?;

    Ok(pk)
}

/// Gathers debug trace(s) from `rpc_url` for block `block_num`.
/// Expects a go-ethereum node with debug & archive capabilities on `rpc_url`.
pub async fn gen_block_witness(
    block_num: &u64,
    rpc_url: &str,
) -> Result<
    (
        witness::Block<Fr>,
        Vec<geth_types::Transaction>,
        u64,
        Vec<Vec<u8>>,
    ),
    Box<dyn std::error::Error>,
> {
    let url = Http::from_str(rpc_url)?;
    let geth_client = GethClient::new(url);
    let builder = BuilderClient::new(geth_client).await?;
    let (builder, eth_block) = builder.gen_inputs(*block_num).await?;
    let keccak_inputs = builder.keccak_inputs()?;
    let txs = eth_block
        .transactions
        .iter()
        .map(geth_types::Transaction::from)
        .collect();
    let gas_used = eth_block.gas_used.as_u64();
    let block = witness::block_convert(&builder.block, &builder.code_db);

    Ok((block, txs, gas_used, keccak_inputs))
}
