#![cfg(feature = "autogen")]

use bus_mapping::mock::BlockData;
use env_logger::Env;
use eth_types::geth_types;
use eth_types::geth_types::GethData;
use eth_types::{address, Word};
use ethers_signers::LocalWallet;
use ethers_signers::Signer;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
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
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write;
use std::fs::File;
use std::io::Write as fwrite;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::witness;
use zkevm_circuits::evm_circuit::{table::FixedTableTag, witness::block_convert};
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::Curve;
use zkevm_circuits::tx_circuit::Group;
use zkevm_circuits::tx_circuit::Secp256k1Affine;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_common::prover::*;

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
}

fn run_assembly<const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_BYTECODE: usize>(
    input_block: witness::Block<Fr>,
    txs: Vec<geth_types::Transaction>,
    keccak_inputs: Vec<Vec<u8>>,
) -> Result<Assembly, String> {
    let chain_id = input_block.context.chain_id;
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();
    let tx_circuit = TxCircuit::new(aux_generator, chain_id.as_u64(), txs);
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
        block: input_block,
        fixed_table_tags: FixedTableTag::iter().collect(),
        tx_circuit,
        keccak_inputs,
        // TODO: why does it succeed if bytecode for tx is > MAX_BYTECODE?
        bytecode_size: MAX_BYTECODE,
    };

    let mut cs = ConstraintSystem::default();
    let config = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA>::configure(&mut cs);
    let mut assembly = Assembly::default();
    // TODO: cs.constants.clone() - private field, but empty
    // assert_eq!(cs.constants.len(), 0);
    let constants = vec![];
    SimpleFloorPlanner::synthesize(&mut assembly, &circuit, config, constants)
        .map_err(|e| e.to_string())?;

    Ok(assembly)
}

macro_rules! estimate {
    ($BLOCK_GAS_LIMIT:expr, $MAX_UNUSED_GAS:expr, $BYTECODE_FN:expr, $scope:expr) => {{
        const LOWEST_GAS_STEP: usize = 2;
        const TX_DATA_ZERO_GAS: usize = 4;
        const BLOCK_GAS_LIMIT: usize = $BLOCK_GAS_LIMIT;
        const TX_GAS_LIMIT: usize = BLOCK_GAS_LIMIT - 21_000;
        const MAX_TXS: usize = BLOCK_GAS_LIMIT / 21_000;
        const MAX_BYTECODE: usize = TX_GAS_LIMIT / LOWEST_GAS_STEP;
        const MAX_CALLDATA: usize = TX_GAS_LIMIT / TX_DATA_ZERO_GAS;

        let bytecode = $BYTECODE_FN(TX_GAS_LIMIT);
        let history_hashes = vec![Word::zero(); 256];
        let block_number = history_hashes.len();
        let input_block;
        let txs: Vec<geth_types::Transaction>;
        let keccak_inputs;
        let chain_id: u64 = 99;

        // prepare block
        {
            let wallet_a = LocalWallet::new(&mut OsRng).with_chain_id(chain_id);
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
            txs = block
                .eth_block
                .transactions
                .iter()
                .map(geth_types::Transaction::from)
                .collect();

            let mut builder =
                BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
            builder
                .handle_block(&block.eth_block, &block.geth_traces)
                .expect("could not handle block tx");
            keccak_inputs = builder.keccak_inputs().expect("keccak_inputs");
            input_block = block_convert(&builder.block, &builder.code_db);
            // check gas used
            {
                let mut cumulative_gas = Word::zero();
                for tx in input_block.txs.iter() {
                    let gas_limit = tx.gas;
                    let gas_left = tx.steps.iter().last().unwrap().gas_left;
                    cumulative_gas = cumulative_gas + (gas_limit - gas_left);
                }
                let diff = input_block.context.gas_limit - cumulative_gas.as_u64();
                assert!(diff <= $MAX_UNUSED_GAS);
            }
        }
        // calculate circuit stats
        {
            let highest_row = run_assembly::<MAX_TXS, MAX_CALLDATA, MAX_BYTECODE>(
                input_block,
                txs,
                keccak_inputs,
            )
            .unwrap()
            .highest_row;
            let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
            let k = log2_ceil(highest_row);
            // TODO: estimate aggregation circuit requirements
            let agg_k = 20;
            let remaining_rows = (1 << k) - highest_row;
            assert!(remaining_rows >= 256);
            let n = 1 << k;
            let pad_to = n - 256;
            let config = CircuitConfig {
                block_gas_limit: BLOCK_GAS_LIMIT,
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                max_bytecode: MAX_BYTECODE,
                min_k: k as usize,
                pad_to,
                min_k_aggregation: agg_k,
            };

            $scope(config, highest_row, remaining_rows);
        }
    }};
}

fn print_table_header(str: &str) {
    println!("##### {}", str);
    println!(
        "| {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
        "BLOCK_GAS_LIMIT",
        "MAX_TXS",
        "MAX_CALLDATA",
        "MAX_BYTECODE",
        "highest row",
        "remaining rows",
        "k"
    );
    println!(
        "| {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
        "-", "-", "-", "-", "-", "-", "-"
    );
}

macro_rules! bytecode_repeat {
    ($code:ident, $repeat:expr, $($args:tt)*) => {{
        for _ in 0..$repeat {
            eth_types::bytecode_internal!($code, $($args)*);
        }
    }};

    ($({$repeat:expr, $($args:tt)*},)*) => {{
        let mut code = eth_types::bytecode::Bytecode::default();

        $(
            bytecode_repeat!(code, $repeat, $($args)*);
        )*

        code
    }};
}

macro_rules! estimate_all {
    ($max_unused_gas:expr, $bytecode:expr, $callback:expr) => {{
        estimate!(63_000, $max_unused_gas, $bytecode, $callback);
        estimate!(150_000, $max_unused_gas, $bytecode, $callback);
        estimate!(300_000, $max_unused_gas, $bytecode, $callback);
    }};
}

/// Generates `circuit_autogen.rs` and prints a markdown table about
/// SuperCircuit parameters.
#[test]
fn proverd_autogen() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // use a map to track the largest circuit parameters for `k`
    let mut params = BTreeMap::<usize, CircuitConfig>::new();
    let mut callback = |config: CircuitConfig, highest_row, remaining_rows| {
        println!(
            "| {:15} | {:7} | {:12} | {:12} | {:12} | {:14} | {:2} |",
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
    };

    // baseline
    {
        print_table_header("baseline");
        let gen_bytecode_stop = |_gas_limit| {
            bytecode_repeat!(
                {
                    1,
                    STOP
                },
            )
        };
        let max_unused_gas = 100_000_000;
        estimate_all!(max_unused_gas, gen_bytecode_stop, callback);
    }
    {
        print_table_header("worst-case evm circuit");
        let gen_bytecode_smod = |gas_limit| {
            let max_deploy_opcodes = (gas_limit - 32_000) / 16;
            let max_contract_size = std::cmp::max(24_576, max_deploy_opcodes);
            let fixed_bytes = 1 + 12;
            let iteration_size = 2;

            let prelude_gas = 2;
            let iteration_gas = 7;

            let max_iterations_bytes = (max_contract_size - fixed_bytes) / iteration_size;
            let mut iterations = (gas_limit - prelude_gas) / iteration_gas;
            let mut loop_enabled = 0;
            if iterations > max_iterations_bytes {
                iterations = max_iterations_bytes;
                loop_enabled = 1;
            }
            let loop_offset: usize = 1 + (iterations * iteration_size);

            log::info!(
                "SMOD: max_contract_size={} iterations={} loop_offset={}",
                max_contract_size,
                iterations,
                loop_offset
            );

            bytecode_repeat!(
                // prelude
                {
                    1,
                    GAS
                },
                // chain SMOD(gas, previous value)
                {
                    iterations,
                    GAS // gas=2
                    SMOD // gas=5
                },
                // loop with remaining gas
                {
                    loop_enabled,
                    JUMPDEST // gas=1
                    GAS  // gas=2
                    SMOD // gas=5
                    PUSH1(44)  // gas=3
                    GAS  // gas=2
                    GT   // gas=3
                    PUSH2(loop_offset) // gas=3
                    JUMPI // gas=10
                    STOP  // gas=0
                },
            )
        };
        let max_unused_gas = 28;
        estimate_all!(max_unused_gas, gen_bytecode_smod, callback);
    }
    {
        print_table_header("worst-case state circuit");
        let gen_bytecode_mload = |gas_limit| {
            let max_deploy_opcodes = (gas_limit - 32_000) / 16;
            let max_contract_size = std::cmp::max(24_576, max_deploy_opcodes);
            let fixed_bytes = 1 + 11;
            let iteration_size = 1;

            // opcode + first memory expansion cost
            let prelude_gas = 2 + 3;
            let iteration_gas = 3;

            let max_iterations_bytes = (max_contract_size - fixed_bytes) / iteration_size;
            let mut iterations = (gas_limit - prelude_gas) / iteration_gas;
            let mut loop_enabled = 0;
            if iterations > max_iterations_bytes {
                iterations = max_iterations_bytes;
                loop_enabled = 1;
            }
            let loop_offset: usize = 1 + (iterations * iteration_size);

            log::info!(
                "MLOAD: max_contract_size={} iterations={} loop_enabled={} loop_offset={}",
                max_contract_size,
                iterations,
                loop_enabled,
                loop_offset
            );

            bytecode_repeat!(
                // prelude
                {
                    1,
                    CALLDATASIZE // gas=2
                },
                // chain mload
                {
                    iterations,
                    MLOAD // gas=3
                },
                {
                    loop_enabled,
                    JUMPDEST // gas=1
                    MLOAD // gas=3
                    PUSH1(40) // gas=3
                    GAS  // gas=2
                    GT   // gas=3
                    PUSH2(loop_offset) // gas=3
                    JUMPI // gas=10
                    STOP  // gas=0
                },
            )
        };
        let max_unused_gas = 28;
        estimate_all!(max_unused_gas, gen_bytecode_mload, callback);
    }

    // generate `circuit_autogen.rs`
    let mut prev_gas = 0;
    let mut str = String::new();
    for (_, config) in params {
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
            {}
            _ => $on_error,
        }}
    }};
}}",
        str
    );

    File::create("./src/circuit_autogen.rs")
        .expect("create circuit_autogen.rs")
        .write_all(str.as_bytes())
        .expect("write circuit_autogen.rs");
}
