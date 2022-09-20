#!/bin/sh

set -xe

trap 'pkill $$' TERM EXIT INT

killall -9 prover_rpcd || true

cargo build --release --bin prover_rpcd
cargo run --release --bin prover_rpcd > PROVER_LOG.txt 2>&1 &
COORDINATOR_DUMMY_PROVER=0 cargo test -- native_deposit
