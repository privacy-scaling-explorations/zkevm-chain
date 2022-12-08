#!/bin/sh

set -x

rm -rf errors
pkill -9 prover_rpcd || true

trap 'pkill --parent $$' TERM EXIT INT

./scripts/compile_contracts.sh

cargo build --release --bin prover_rpcd
env time --output PROVER_STATS.txt --verbose -- \
  cargo run --release --bin prover_rpcd 2>&1 | xz > PROVER_LOG.txt.xz &
PID=$!

# sleep a bit in case the geth nodes are not up yet
sleep 3

# finalize any leftover blocks
COORDINATOR_DUMMY_PROVER=true cargo test -p coordinator -- finalize_chain --ignored || exit 1

# now run all default tests
COORDINATOR_DUMMY_PROVER=false cargo test -p coordinator -- $@
status=$?
FAILED_BLOCKS=$(./scripts/rpc_prover.sh info | jq -cr '.result.tasks | map(select(.result.Err)) | map(.options.block) | .[]')

pkill -9 prover_rpcd || true
wait $PID
cat PROVER_STATS.txt
cat PROVER_PERF.txt

if [ $status -eq 0 ]; then
  exit 0
fi

# if there are not failed proof requests, then something else failed
if [ "${FAILED_BLOCKS}" = "" ]; then
  exit 1
fi

# error collection
mkdir errors

for block_num in $FAILED_BLOCKS; do
  ./scripts/get_block_fixtures.sh $COORDINATOR_L2_RPC_URL $block_num
  mkdir -p errors/$block_num
  mv block_hashes.json block.json prestate.json errors/$block_num/
done

mv PROVER_LOG.txt.xz errors/
