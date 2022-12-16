use crate::genesis::get_max_contract_size;

#[macro_export]
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

pub fn gen_bytecode_smod(gas_limit: usize) -> eth_types::Bytecode {
    let max_contract_size = get_max_contract_size(gas_limit);
    let fixed_bytes = 5;
    let iteration_size = 2;
    let iterations = (max_contract_size - fixed_bytes) / iteration_size;
    let loop_offset: usize = 1;
    bytecode_repeat!(
        // prelude
        {
            1,
            GAS // gas=2
            JUMPDEST // gas=1
        },
        // chain SMOD(gas, previous value)
        {
            iterations,
            GAS // gas=2
            SMOD // gas=5
        },
        // loop with remaining gas
        {
            1,
            PUSH1(loop_offset) // gas=3
            JUMP // gas=8
        },
    )
}

pub fn gen_bytecode_mload(gas_limit: usize) -> eth_types::Bytecode {
    let max_contract_size = get_max_contract_size(gas_limit);
    let fixed_bytes = 5;
    let iterations = max_contract_size - fixed_bytes;
    let loop_offset: usize = 1;
    bytecode_repeat!(
        // prelude
        {
            1,
            CALLDATASIZE // gas=2
            JUMPDEST // gas=1
        },
        // chain mload
        {
            iterations,
            MLOAD // gas=3
        },
        {
            1,
            PUSH1(loop_offset) // gas=3
            JUMP // gas=8
        },
    )
}

pub fn gen_bytecode_keccak_0_32(gas_limit: usize) -> eth_types::Bytecode {
    let max_contract_size = get_max_contract_size(gas_limit);
    let fixed_bytes = 6;
    let iteration_size = 4;
    let iterations = (max_contract_size - fixed_bytes) / iteration_size;
    let loop_offset: usize = 2;
    bytecode_repeat!(
        {
            1,
            PUSH1(32) // gas=3
            JUMPDEST // gas=1
        },
        {
            iterations,
            DUP1 // gas=3
            RETURNDATASIZE // gas=2
            SHA3 // gas=30 + 6 + (memory expansion once)
            POP // gas=2
        },
        {
            1,
            PUSH1(loop_offset) // gas=3
            JUMP // gas=8
        },
    )
}
