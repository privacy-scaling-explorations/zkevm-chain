#!/bin/sh

set -x

rm -rf errors
pkill -9 prover_rpcd || true

trap 'pkill --parent $$' TERM EXIT INT

./scripts/compile_contracts.sh

cargo build --release --bin prover_rpcd
env time --output PROVER_STATS.txt --verbose -- \
  perf stat -I 300000 \
  -o PROVER_PERF.txt \
  -e stalled-cycles-backend \
  -e stalled-cycles-frontend \
  -e instructions \
  -e branch-instructions \
  -e ic_fetch_stall.ic_stall_any \
  -e ic_fetch_stall.ic_stall_back_pressure \
  -e ic_fetch_stall.ic_stall_dq_empty \
  -e sse_avx_stalls \
  -e all_data_cache_accesses \
  -e all_tlbs_flushed \
  -e l1_data_cache_fills_all \
  -e fp_ret_sse_avx_ops.all \
  -e l1_data_cache_fills_all \
  -e l2_cache_accesses_from_dc_misses \
  -e l2_cache_accesses_from_ic_misses \
  -e ic_tag_hit_miss.all_instruction_cache_accesses \
  -e ic_tag_hit_miss.instruction_cache_hit \
  -e ic_tag_hit_miss.instruction_cache_miss \
  -- \
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
