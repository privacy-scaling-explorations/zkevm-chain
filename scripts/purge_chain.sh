#!/bin/sh

set -xe

docker compose down
docker volume rm zkevm-chain_l1-testnet-geth zkevm-chain_leader-testnet-geth zkevm-chain_bootnode
