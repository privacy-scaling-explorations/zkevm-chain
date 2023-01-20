#!/bin/sh

set -xe

trap 'pkill --parent $$' TERM EXIT INT

pkill -9 prover_rpcd || true

cargo build --release --bin prover_rpcd

if [ "${DEV_PERF}" ]; then
  perf record -e task-clock -F 1000 -g -- cargo run --release --bin prover_rpcd > PROVER_LOG.txt 2>&1 &
else
  cargo run --release --bin prover_rpcd > PROVER_LOG.txt 2>&1 &
fi

COORDINATOR_DUMMY_PROVER=false cargo test -- $@
