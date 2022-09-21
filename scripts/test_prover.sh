#!/bin/sh

set -xe

trap 'pkill --parent $$' TERM EXIT INT

pkill -9 prover_rpcd || true

cargo build --release --bin prover_rpcd
PROVERD_ENABLE_CIRCUIT_INSTANCE=1 cargo run --release --bin prover_rpcd > PROVER_LOG.txt 2>&1 &
COORDINATOR_DUMMY_PROVER=0 cargo test -- $@
