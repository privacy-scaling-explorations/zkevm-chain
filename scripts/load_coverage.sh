#!/bin/sh

curl -f "$COORDINATOR_L1_RPC_URL"/reload
curl -f "$COORDINATOR_L2_RPC_URL"/reload
