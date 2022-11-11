#[macro_export]
macro_rules! match_circuit_params {
    ($gas_used:expr, $on_match:expr, $on_error:expr) => {
        match $gas_used {
            0..=63000 => {
                const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
                    block_gas_limit: 63000,
                    max_txs: 3,
                    max_calldata: 10500,
                    max_bytecode: 21000,
                    max_rws: 491520,
                    min_k: 19,
                    pad_to: 491520,
                    min_k_aggregation: 20,
                    keccak_padding: 1000,
                };
                $on_match
            }
            63001..=150000 => {
                const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
                    block_gas_limit: 150000,
                    max_txs: 7,
                    max_calldata: 32250,
                    max_bytecode: 64500,
                    max_rws: 1015808,
                    min_k: 20,
                    pad_to: 1015808,
                    min_k_aggregation: 20,
                    keccak_padding: 2380,
                };
                $on_match
            }
            150001..=300000 => {
                const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
                    block_gas_limit: 300000,
                    max_txs: 14,
                    max_calldata: 69750,
                    max_bytecode: 139500,
                    max_rws: 2064384,
                    min_k: 21,
                    pad_to: 2064384,
                    min_k_aggregation: 20,
                    keccak_padding: 4761,
                };
                $on_match
            }

            _ => $on_error,
        }
    };
}
