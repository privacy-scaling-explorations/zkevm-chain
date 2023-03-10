#!/bin/sh

set -eux

# data collection
TEST_DATE=$(date -uR)
PROVER_VERSION=$(cat PROVER_VERSION.txt)
ELAPSED_TIME=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==5 {print $2}')
NUM_CPUS=$(cat /proc/cpuinfo | grep processor | wc -l)
CPU_PERCENT=$(cat PROVER_STATS.txt | awk -F ': ' "FNR==4 {print \$2 / $NUM_CPUS}")
MEM_MAX_MB=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==10 {print $2 / 1024}')
PAGE_FAULTS=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==13 {print $2}')
PAGE_SIZE=$(cat PROVER_STATS.txt | awk -F ': ' 'FNR==22 {print $2}')

# assuming only 1 prover task
TASK=$(cat PROVER_DATA.txt | jq -c '.tasks[0]')

ERROR_DESCRIPTION=$(printf '%s' "${TASK}" | jq -c '.result.Err[0:255]')
ERROR_URL="https://github.com/${GITHUB_REPOSITORY}/tree/prover-error-${TEST_ID}/errors-$(git -c safe.directory='*' rev-parse HEAD)"
CIRCUIT_LABEL=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.label')
CIRCUIT_MS_INIT=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.circuit')
CIRCUIT_MS_VK=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.vk')
CIRCUIT_MS_PK=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.pk')
CIRCUIT_MS_PROOF=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.proof')
CIRCUIT_MS_VERIFY=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.verify')
CIRCUIT_MS_MOCK=$(printf '%s' "${TASK}" | jq -c '.result.Ok.circuit.aux.mock')
AGGREGATE_LABEL=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.label')
AGGREGATE_MS_INIT=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.circuit')
AGGREGATE_MS_VK=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.vk')
AGGREGATE_MS_PK=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.pk')
AGGREGATE_MS_PROOF=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.proof')
AGGREGATE_MS_VERIFY=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.verify')
AGGREGATE_MS_PROTOCOL=$(printf '%s' "${TASK}" | jq -c '.result.Ok.aggregation.aux.protocol')
DUMMY_FLAG='false'

SQL=$(cat << EOF
CREATE TABLE IF NOT EXISTS testresults_zkevm_chain_integration_github (
    id bigint,
    date datetime,
    github_ref varchar(255),
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
    aggregation_ms_protocol integer,
    dummy boolean
);
INSERT INTO testresults_zkevm_chain_integration_github
VALUES (
  null,
  "${TEST_DATE}",
  "${GITHUB_REF}",
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
  ${AGGREGATE_MS_PROTOCOL},
  ${DUMMY_FLAG}
);
EOF
)

echo "${SQL}"
