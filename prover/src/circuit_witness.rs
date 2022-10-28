use bus_mapping::circuit_input_builder::Block;
use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::circuit_input_builder::CircuitsParams;
use bus_mapping::rpc::GethClient;
use bus_mapping::state_db::CodeDB;
use eth_types::geth_types;
use eth_types::Address;
use eth_types::ToBigEndian;
use eth_types::Word;
use eth_types::H256;
use eth_types::U256;
use ethers_providers::Http;
use halo2_proofs::halo2curves::bn256::Fr;
use std::str::FromStr;
use zkevm_circuits::evm_circuit;
use zkevm_circuits::pi_circuit::PublicData;
use zkevm_common::prover::CircuitConfig;

/// Wrapper struct for circuit witness data.
pub struct CircuitWitness {
    pub circuit_config: CircuitConfig,
    pub eth_block: eth_types::Block<eth_types::Transaction>,
    pub block: bus_mapping::circuit_input_builder::Block,
    pub code_db: bus_mapping::state_db::CodeDB,
    pub keccak_inputs: Vec<Vec<u8>>,
}

impl CircuitWitness {
    pub fn dummy(circuit_config: CircuitConfig) -> Result<Self, String> {
        let history_hashes = vec![Word::zero(); 256];
        let mut eth_block: eth_types::Block<eth_types::Transaction> = eth_types::Block::default();
        eth_block.author = Some(Address::zero());
        eth_block.number = Some(history_hashes.len().into());
        eth_block.base_fee_per_gas = Some(0.into());
        eth_block.hash = Some(eth_block.parent_hash);
        eth_block.gas_limit = circuit_config.block_gas_limit.into();

        let circuit_params = CircuitsParams {
            max_rws: circuit_config.max_rws,
            max_txs: circuit_config.max_txs,
        };
        let keccak_inputs = Vec::new();
        let code_db = CodeDB::new();
        let chain_id = U256::from(99);
        let block = Block::new(
            chain_id,
            history_hashes,
            U256::default(),
            &eth_block,
            circuit_params,
        )
        .map_err(|e| e.to_string())?;

        Ok(Self {
            circuit_config,
            eth_block,
            block,
            code_db,
            keccak_inputs,
        })
    }

    /// Gathers debug trace(s) from `rpc_url` for block `block_num`.
    /// Expects a go-ethereum node with debug & archive capabilities on `rpc_url`.
    pub async fn from_rpc(
        block_num: &u64,
        rpc_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let url = Http::from_str(rpc_url)?;
        let geth_client = GethClient::new(url);
        // TODO: add support for `eth_getHeaderByNumber`
        let block = geth_client.get_block_by_number((*block_num).into()).await?;
        let circuit_config =
            crate::match_circuit_params!(block.gas_used.as_usize(), CIRCUIT_CONFIG, {
                return Err(format!(
                    "No circuit parameters found for block with gas used={}",
                    block.gas_used
                )
                .into());
            });
        let circuit_params = CircuitsParams {
            max_rws: circuit_config.max_rws,
            max_txs: circuit_config.max_txs,
        };
        let builder = BuilderClient::new(geth_client, circuit_params).await?;
        let (builder, eth_block) = builder.gen_inputs(*block_num).await?;
        let keccak_inputs = builder.keccak_inputs()?;

        Ok(Self {
            circuit_config,
            eth_block,
            block: builder.block,
            code_db: builder.code_db,
            keccak_inputs,
        })
    }

    pub fn evm_witness(&self) -> (zkevm_circuits::witness::Block<Fr>, Vec<Vec<u8>>) {
        let mut block = evm_circuit::witness::block_convert(&self.block, &self.code_db);
        block.evm_circuit_pad_to = self.circuit_config.pad_to;
        let keccak_inputs = self.keccak_inputs.clone();

        (block, keccak_inputs)
    }

    pub fn gas_used(&self) -> u64 {
        self.eth_block.gas_used.as_u64()
    }

    pub fn txs(&self) -> Vec<geth_types::Transaction> {
        let txs = self
            .eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from)
            .collect();

        txs
    }

    pub fn public_data(&self) -> PublicData {
        let chain_id = self.block.chain_id;
        let eth_block = self.eth_block.clone();
        let history_hashes = self.block.history_hashes.clone();
        let block_constants = geth_types::BlockConstants {
            coinbase: eth_block.author.expect("coinbase"),
            timestamp: eth_block.timestamp,
            number: eth_block.number.expect("number"),
            difficulty: eth_block.difficulty,
            gas_limit: eth_block.gas_limit,
            base_fee: eth_block.base_fee_per_gas.unwrap_or_default(),
        };
        let prev_state_root = H256::from(self.block.prev_state_root.to_be_bytes());

        PublicData {
            chain_id,
            history_hashes,
            eth_block,
            block_constants,
            prev_state_root,
        }
    }
}
