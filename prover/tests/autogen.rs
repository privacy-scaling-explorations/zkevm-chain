#![cfg(feature = "autogen")]
#![feature(const_cmp)]
#![feature(once_cell)]

use bus_mapping::circuit_input_builder::CircuitsParams;
use bus_mapping::mock::BlockData;
use env_logger::Env;
use eth_types::geth_types::GethData;
use eth_types::{address, Word};
use ethers_signers::LocalWallet;
use ethers_signers::Signer;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Any;
use halo2_proofs::plonk::Assigned;
use halo2_proofs::plonk::Assignment;
use halo2_proofs::plonk::Challenge;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::plonk::FloorPlanner;
use halo2_proofs::plonk::Instance;
use halo2_proofs::plonk::Selector;
use mock::TestContext;
use paste::paste;
use prover::circuit_witness::CircuitWitness;
use prover::circuits::gen_super_circuit;
use prover::utils::fixed_rng;
use prover::Fr;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::fs::File;
use std::io::Write as fwrite;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use zkevm_circuits::evm_circuit::witness::block_convert;
use zkevm_common::prover::*;
use zkevm_dev::bytecode::*;

#[derive(Debug, Default)]
struct Assembly {
    highest_row: usize,
}

impl Assembly {
    fn track_row(&mut self, row: usize) {
        if row > self.highest_row {
            self.highest_row = row;
        }
    }
}

impl<F: Field> Assignment<F> for Assembly {
    fn enter_region<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about regions in this context.
    }

    fn exit_region(&mut self) {
        // Do nothing; we don't care about regions in this context.
    }

    fn enable_selector<A, AR>(
        &mut self,
        _: A,
        _selector: &Selector,
        row: usize,
    ) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.track_row(row);

        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, row: usize) -> Result<Value<F>, Error> {
        assert!(row <= self.highest_row);
        Ok(Value::unknown())
    }

    fn assign_advice<V, VR, A, AR>(
        &mut self,
        _: A,
        _: Column<Advice>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.track_row(row);

        Ok(())
    }

    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        _: A,
        _: Column<Fixed>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.track_row(row);

        Ok(())
    }

    fn copy(
        &mut self,
        _: Column<Any>,
        left_row: usize,
        _: Column<Any>,
        right_row: usize,
    ) -> Result<(), Error> {
        self.track_row(left_row);
        self.track_row(right_row);

        Ok(())
    }

    fn fill_from_row(
        &mut self,
        _: Column<Fixed>,
        from_row: usize,
        _to: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        self.track_row(from_row);

        Ok(())
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self, _: Option<String>) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_challenge(&self, _: Challenge) -> Value<F> {
        Value::unknown()
    }

    fn annotate_column<A, AR>(&mut self, _annotation: A, _column: Column<Any>)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // Do nothing.
    }
}

fn estimate_rows<ConcreteCircuit: Circuit<Fr>>(circuit: &ConcreteCircuit) -> Result<usize, String> {
    let mut cs = ConstraintSystem::default();
    let config = ConcreteCircuit::configure(&mut cs);
    let mut assembly = Assembly::default();
    let constants = cs.constants();
    SimpleFloorPlanner::synthesize(&mut assembly, circuit, config, constants.to_vec())
        .map_err(|e| e.to_string())?;

    Ok(assembly.highest_row + cs.blinding_factors() + 1)
}

macro_rules! estimate {
    ($BLOCK_GAS_LIMIT:expr, $MAX_UNUSED_GAS:expr, $BYTECODE_FN:expr) => {{
        const LOWEST_GAS_STEP: usize = 2;
        const TX_DATA_ZERO_GAS: usize = 4;
        const BLOCK_GAS_LIMIT: usize = $BLOCK_GAS_LIMIT;
        const TX_GAS_LIMIT: usize = BLOCK_GAS_LIMIT - 21_000;
        const MAX_TXS: usize = BLOCK_GAS_LIMIT / 21_000;
        // TODO: why +58?
        const MAX_BYTECODE: usize = std::cmp::max(24_576 + 58, TX_GAS_LIMIT / LOWEST_GAS_STEP);
        const MAX_CALLDATA: usize = TX_GAS_LIMIT / TX_DATA_ZERO_GAS;
        // TODO
        // Right now, it only accounts for MLOAD step height.
        // - Investigate other fixed sources of rw steps.
        // - Add support for querying the most expensive opcode here.
        const MAX_RWS: usize = (64 * MAX_TXS) + ((TX_GAS_LIMIT * 1133) / 100);
        const KECCAK_WORD_GAS: usize = 6;
        const COPY_GAS: usize = 3;
        // TODO: doesn't account for instruction + memory expansion
        const MAX_COPY_BYTES: usize = (TX_GAS_LIMIT / COPY_GAS) * 32;
        const MAX_COPY_ROWS: usize = (MAX_COPY_BYTES * 2) + 2;
        const MAX_EXP_STEPS: usize = TX_GAS_LIMIT / 10;

        let bytecode = $BYTECODE_FN(TX_GAS_LIMIT);
        let history_hashes = vec![Word::one(); 256];
        let block_number = history_hashes.len();
        let chain_id: u64 = 99;
        // test with this config. If the padding parameters are not high enough, then circuit
        // should fail.
        let mut circuit_config = CircuitConfig {
            block_gas_limit: BLOCK_GAS_LIMIT,
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_bytecode: MAX_BYTECODE,
            max_rws: MAX_RWS,
            max_copy_rows: MAX_COPY_ROWS,
            max_exp_steps: MAX_EXP_STEPS,
            min_k: 0,
            pad_to: 0,
            min_k_aggregation: 0,
            // TODO: proper worst-case estimate
            keccak_padding: (BLOCK_GAS_LIMIT / KECCAK_WORD_GAS) * 32,
        };
        let circuit_witness;

        // prepare block
        {
            let wallet_a = LocalWallet::new(&mut fixed_rng()).with_chain_id(chain_id);
            let addr_a = wallet_a.address();
            let addr_b = address!("0x000000000000000000000000000000000000BBBB");
            let mut wallets = HashMap::new();
            wallets.insert(wallet_a.address(), wallet_a);

            let mut block: GethData = TestContext::<2, 1>::new(
                Some(history_hashes),
                |accs| {
                    accs[0]
                        .address(addr_b)
                        .balance(Word::from(1u64 << 20))
                        .code(bytecode.clone());
                    accs[1].address(addr_a).balance(Word::from(1u64 << 20));
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[1].address)
                        .to(accs[0].address)
                        .gas(Word::from(BLOCK_GAS_LIMIT));
                },
                |block, _tx| {
                    block
                        .number(block_number as u64)
                        .gas_limit(BLOCK_GAS_LIMIT.into())
                        .chain_id(chain_id.into())
                },
            )
            .unwrap()
            .into();
            block.sign(&wallets);

            let circuit_params = CircuitsParams {
                max_txs: circuit_config.max_txs,
                max_calldata: circuit_config.max_calldata,
                max_bytecode: circuit_config.max_bytecode,
                max_rws: circuit_config.max_rws,
                max_copy_rows: circuit_config.max_copy_rows,
                max_exp_steps: circuit_config.max_exp_steps,
                max_evm_rows: circuit_config.pad_to,
                max_keccak_rows: circuit_config.keccak_padding,
            };
            let mut builder =
                BlockData::new_from_geth_data_with_params(block.clone(), circuit_params)
                    .new_circuit_input_builder();
            builder
                .handle_block(&block.eth_block, &block.geth_traces)
                .expect("could not handle block tx");

            // check gas used
            {
                let mut cumulative_gas = Word::zero();
                let input_block =
                    block_convert::<Fr>(&builder.block, &builder.code_db).expect("block_convert");
                for tx in input_block.txs.iter() {
                    let gas_limit = tx.gas;
                    let gas_left = tx.steps.iter().last().unwrap().gas_left;
                    cumulative_gas = cumulative_gas + (gas_limit - gas_left);
                }
                let diff = input_block.context.gas_limit - cumulative_gas.as_u64();
                assert!(diff <= $MAX_UNUSED_GAS);
            }

            circuit_witness = CircuitWitness {
                circuit_config: circuit_config.clone(),
                eth_block: block.eth_block,
                block: builder.block,
                code_db: builder.code_db,
            };
        }
        // calculate circuit stats
        {
            circuit_config.pad_to = MAX_RWS;
            let circuit = gen_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_RWS, MAX_COPY_ROWS, _>(
                &circuit_witness,
                fixed_rng(),
            )
            .expect("gen_static_circuit");
            let highest_row = estimate_rows(&circuit).unwrap();
            let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
            let k = log2_ceil(highest_row) as usize;
            let remaining_rows = (1 << k) - highest_row;
            circuit_config.min_k = k;
            // TODO: estimate aggregation circuit requirements
            circuit_config.min_k_aggregation = 26;

            (circuit_config, highest_row, remaining_rows)
        }
    }};
}

fn print_table_header() {
    println!(
        "| {:10} | {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
        "label",
        "BLOCK_GAS_LIMIT",
        "MAX_TXS",
        "MAX_CALLDATA",
        "MAX_BYTECODE",
        "highest row",
        "remaining rows",
        "k"
    );
    println!(
        "| {:10} | {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
        "-", "-", "-", "-", "-", "-", "-", "-"
    );
}

macro_rules! gen_fn {
    ($label:expr, $bytecode_fn:expr, $max_unused_gas:expr, $block_gas:expr) => {
        paste! {
            #[test]
            fn [<autogen_circuit_config_ $bytecode_fn _ $block_gas>]() {
                let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();
                let (config, highest_row, remaining_rows) = estimate!($block_gas, $max_unused_gas, $bytecode_fn);
                write_config($label, config, highest_row, remaining_rows);
            }
        }
    };
}

macro_rules! estimate_all {
    ($label:expr, $bytecode:expr, $max_unused_gas:expr) => {
        gen_fn!($label, $bytecode, $max_unused_gas, 63_000);
        gen_fn!($label, $bytecode, $max_unused_gas, 300_000);
    };
}

estimate_all!("worst-case evm circuit", gen_bytecode_smod, 0);
estimate_all!("worst-case state circuit", gen_bytecode_mload, 0);
estimate_all!(
    "worst-case keccak (invocations) circuit",
    gen_bytecode_keccak_0_32,
    0
);

// use a map to track the largest circuit parameters for `k`
type ConfigMap = BTreeMap<usize, CircuitConfig>;
static CONFIG_MAP: LazyLock<Arc<Mutex<ConfigMap>>> = LazyLock::new(|| {
    print_table_header();
    Arc::new(Mutex::new(ConfigMap::new()))
});

/// Generates `circuit_autogen.rs` and prints a markdown table about
/// SuperCircuit parameters.
fn write_config(label: &str, config: CircuitConfig, highest_row: usize, remaining_rows: usize) {
    let mut params = CONFIG_MAP.lock().unwrap();
    println!(
        "| {:10} | {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
        label,
        config.block_gas_limit,
        config.max_txs,
        config.max_calldata,
        config.max_bytecode,
        highest_row,
        remaining_rows,
        config.min_k,
    );
    if let Some(val) = params.get(&config.min_k) {
        // don't update if the previous entity has a lower gas limit
        if val.block_gas_limit < config.block_gas_limit {
            return;
        }
    }
    params.insert(config.min_k, config);

    // generate `circuit_autogen.rs`
    let mut prev_gas = 0;
    let mut str = String::new();
    for config in params.values() {
        write!(
            str,
            "{}..={} => {{
                const CIRCUIT_CONFIG: CircuitConfig = {:#?};
                $on_match
            }},
            ",
            prev_gas, config.block_gas_limit, config,
        )
        .expect("fmt write");
        prev_gas = config.block_gas_limit + 1;
    }

    let str = format!(
        "
#[macro_export]
macro_rules! match_circuit_params {{
    ($gas_used:expr, $on_match:expr, $on_error:expr) => {{
        match $gas_used {{
            {str}
            _ => $on_error,
        }}
    }};
}}"
    );

    File::create("./src/circuit_autogen.rs")
        .expect("create circuit_autogen.rs")
        .write_all(str.as_bytes())
        .expect("write circuit_autogen.rs");

    let mut str = String::new();
    for config in params.values() {
        write!(
            str,
            "
    if (blockGasLimit <= {}) {{
      return ({}, {});
    }}
    ",
            config.block_gas_limit, config.max_txs, config.max_calldata,
        )
        .expect("fmt write");
    }

    let str = format!(
        "
// SPDX-License-Identifier: MIT
pragma solidity <0.9.0;
contract CircuitConfig {{
  function _getCircuitConfig (uint256 blockGasLimit) internal pure returns (uint256, uint256) {{
    {str}
    revert(\"CIRCUIT_CONFIG\");
  }}
}}"
    );

    File::create("../contracts/generated/CircuitConfig.sol")
        .expect("CircuitConfig.sol")
        .write_all(str.as_bytes())
        .expect("CircuitConfig.sol");
}
