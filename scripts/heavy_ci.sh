#!/bin/sh

set -x

pkill -9 prover_rpcd || true

trap 'pkill --parent $$' TERM EXIT INT

./scripts/compile_contracts.sh

cargo build --release --bin prover_rpcd
env time --output PROVER_STATS.txt --verbose -- cargo run --release --bin prover_rpcd 2>&1 | xz > PROVER_LOG.txt.xz &
PID=$!

# sleep a bit in case the geth nodes are not up yet
sleep 3

COORDINATOR_DUMMY_PROVER=false cargo test -p coordinator
status=$?

pkill -9 prover_rpcd || true
wait $PID
cat PROVER_STATS.txt

if [ $status -eq 0 ]; then
  exit 0
fi

FAILED_BLOCKS=$(./scripts/rpc_prover.sh info | jq -cr '.result.tasks | map(select(.result.Err)) | map(.options.block) | .[]')

rm -rf errors
mkdir errors

for block_num in $FAILED_BLOCKS; do
  ./scripts/get_block_fixtures.sh $COORDINATOR_L2_RPC_URL $block_num
  mkdir -p errors/$block_num
  mv block_hashes.json block.json prestate.json errors/$block_num/
done

mv PROVER_LOG.txt.xz errors/
