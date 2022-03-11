#!/bin/sh

docker run --rm -w /app -v $(pwd):/app \
  ethereum/solc:0.8.12 \
  --overwrite \
  --metadata-hash none \
  --asm-json \
  --storage-layout \
  --bin \
  --bin-runtime \
  --abi \
  -o build/contracts/ \
  $(find contracts/ -iname '*.sol')
