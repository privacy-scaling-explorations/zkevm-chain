#!/bin/sh

set -x

curl -f "$COORDINATOR_L1_RPC_URL"/.lcov > build/coverage-report.lcov
curl -f "$COORDINATOR_L2_RPC_URL"/.lcov >> build/coverage-report.lcov
