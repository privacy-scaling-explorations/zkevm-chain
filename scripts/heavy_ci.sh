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
perf stat --pid $PID -I 300000 -o PROVER_PERF.txt \
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
  -e ic_tag_hit_miss.instruction_cache_miss &

# sleep a bit in case the geth nodes are not up yet
sleep 3

# finalize any leftover blocks
COORDINATOR_DUMMY_PROVER=true cargo test -p coordinator -- finalize_chain --ignored || exit 1

# now run all default tests
COORDINATOR_DUMMY_PROVER=false cargo test -p coordinator -- $@
status=$?
PROVER_DATA=$(./scripts/rpc_prover.sh info | jq -cr '.result')
FAILED_BLOCKS=$(printf -- "${PROVER_DATA}" | jq -cr '.tasks | map(select(.result.Err)) | map(.options.block) | .[]')

pkill -9 prover_rpcd || true
wait $PID
cat PROVER_STATS.txt
cat PROVER_PERF.txt

# data collection
TEST_ID=$(head --bytes 8 /dev/random | xxd -ps)
TEST_DATE=$(date -uR)
PROVER_VERSION=$(cargo run --release --bin prover_rpcd -- --version)
ELAPSED_TIME=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==5 {print $2}')
NUM_CPUS=$(cat /proc/cpuinfo | grep processor | wc -l)
CPU_PERCENT=$(cat PROVER_STATS.txt | awk -F ': ' "FNR==4 {print \$2 / $NUM_CPUS}")
MEM_MAX_MB=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==10 {print $2 / 1024}')
PAGE_FAULTS=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==13 {print $2}')
PAGE_SIZE=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==22 {print $2}')

# assuming only 1 prover task
TASK=$(printf -- "${PROVER_DATA}" | jq -c '.tasks[0]')

ERROR_DESCRIPTION=$(printf -- "${TASK}" | jq -c '.result.Err[0:255]')
ERROR_URL="https://github.com/${GITHUB_REPOSITORY}/tree/prover-error-${TEST_ID}/errors-$(git -c safe.directory='*' rev-parse HEAD)"
CIRCUIT_LABEL=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.label')
CIRCUIT_MS_INIT=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.circuit')
CIRCUIT_MS_VK=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.vk')
CIRCUIT_MS_PK=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.pk')
CIRCUIT_MS_PROOF=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.proof')
CIRCUIT_MS_VERIFY=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.verify')
CIRCUIT_MS_MOCK=$(printf -- "${TASK}" | jq -c '.result.Ok.circuit.aux.mock')
AGGREGATE_LABEL=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.label')
AGGREGATE_MS_INIT=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.circuit')
AGGREGATE_MS_VK=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.vk')
AGGREGATE_MS_PK=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.pk')
AGGREGATE_MS_PROOF=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.proof')
AGGREGATE_MS_VERIFY=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.verify')
AGGREGATE_MS_PROTOCOL=$(printf -- "${TASK}" | jq -c '.result.Ok.aggregation.aux.protocol')

SQL=$(cat << EOF
CREATE TABLE IF NOT EXISTS zkevm_chain_integration_github (
    id char(16),
    date datetime,
    prover_version varchar(255),
    elapsed_time varchar(255),
    num_cpus integer,
    cpu_percent float,
    mem_max_mb float,
    page_faults integer,
    page_size integer,
    error_description varchar(255),
    error_url varchar(255),
    circuit_label varchar(255),
    circuit_ms_init integer,
    circuit_ms_vk integer,
    circuit_ms_pk integer,
    circuit_ms_proof integer,
    circuit_ms_verify integer,
    circuit_ms_mock integer,
    aggregation_label varchar(255),
    aggregation_ms_init integer,
    aggregation_ms_vk integer,
    aggregation_ms_pk integer,
    aggregation_ms_proof integer,
    aggregation_ms_verify integer,
    aggregation_ms_protocol integer
);
INSERT INTO zkevm_chain_integration_github
VALUES (
  "${TEST_ID}",
  "${TEST_DATE}",
  "${PROVER_VERSION}",
  "${ELAPSED_TIME}",
  ${NUM_CPUS},
  ${CPU_PERCENT},
  ${MEM_MAX_MB},
  ${PAGE_FAULTS},
  ${PAGE_SIZE},
  ${ERROR_DESCRIPTION},
  "${ERROR_URL}",
  ${CIRCUIT_LABEL},
  ${CIRCUIT_MS_INIT},
  ${CIRCUIT_MS_VK},
  ${CIRCUIT_MS_PK},
  ${CIRCUIT_MS_PROOF},
  ${CIRCUIT_MS_VERIFY},
  ${CIRCUIT_MS_MOCK},
  ${AGGREGATE_LABEL},
  ${AGGREGATE_MS_INIT},
  ${AGGREGATE_MS_VK},
  ${AGGREGATE_MS_PK},
  ${AGGREGATE_MS_PROOF},
  ${AGGREGATE_MS_VERIFY},
  ${AGGREGATE_MS_PROTOCOL}
);
EOF
)
# prefix every line
printf -- "${SQL}" | awk '{print "__SQL_TEST_RUN__" $0}'

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
