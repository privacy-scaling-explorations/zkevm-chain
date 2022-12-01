#!/bin/sh

set -xe

COORDINATOR_L1_RPC_URL=http://coverage-l1:8545
COORDINATOR_L2_RPC_URL=http://coverage-l2:8545

curl -f "$COORDINATOR_L1_RPC_URL"/reload
curl -f "$COORDINATOR_L2_RPC_URL"/reload

cargo test "$@"

curl -f "$COORDINATOR_L1_RPC_URL"/.lcov > build/coverage-report.lcov
curl -f "$COORDINATOR_L2_RPC_URL"/.lcov >> build/coverage-report.lcov
