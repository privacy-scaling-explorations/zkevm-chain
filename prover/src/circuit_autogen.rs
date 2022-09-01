#[macro_export]
macro_rules! match_circuit_params {
    ($gas_used:expr, $on_match:expr, $on_error:expr) => {
        match $gas_used {
            0..=50000 => {
                const BLOCK_GAS_LIMIT: usize = 50000;
                const MAX_TXS: usize = 2;
                const MAX_CALLDATA: usize = 7250;
                const MAX_BYTECODE: usize = 9666;
                const MIN_K: usize = 19;
                const STATE_CIRCUIT_PAD_TO: usize = 524032;
                $on_match
            }
            50001..=100000 => {
                const BLOCK_GAS_LIMIT: usize = 100000;
                const MAX_TXS: usize = 4;
                const MAX_CALLDATA: usize = 19750;
                const MAX_BYTECODE: usize = 26333;
                const MIN_K: usize = 20;
                const STATE_CIRCUIT_PAD_TO: usize = 1048320;
                $on_match
            }
            100001..=300000 => {
                const BLOCK_GAS_LIMIT: usize = 300000;
                const MAX_TXS: usize = 14;
                const MAX_CALLDATA: usize = 69750;
                const MAX_BYTECODE: usize = 93000;
                const MIN_K: usize = 21;
                const STATE_CIRCUIT_PAD_TO: usize = 2096896;
                $on_match
            }

            _ => $on_error,
        }
    };
}
