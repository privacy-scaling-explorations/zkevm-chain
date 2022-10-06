#!/bin/sh

set -x

pkill -9 prover_rpcd || true

trap 'pkill --parent $$' TERM EXIT INT

./scripts/compile_contracts.sh

cargo build --release --bin prover_rpcd
cargo run --release --bin prover_rpcd > PROVER_LOG.txt 2>&1 &
COORDINATOR_DUMMY_PROVER=0 cargo test -- --nocapture
status=$?
cat PROVER_LOG.txt

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

cat PROVER_LOG.txt | xz > errors/PROVER_LOG.txt.xz
