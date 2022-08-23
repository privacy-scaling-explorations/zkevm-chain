#!/bin/sh

ROOT="$(dirname $0)/.."

for file in $(find "$ROOT"/contracts/templates/ -iname '*.sol'); do
  name=$(basename $file)
  generated="$ROOT"/contracts/generated/$name
  cp "$file" "$generated"
  for inc in $(cat "$file" | grep "//@INCLUDE:"); do
    template=$(echo "$inc" | awk -F":" '{print $NF}')
    sed -i -e "\#$inc#r $ROOT/contracts/templates/$template" "$generated"
  done
done

SOLC=$(which solc || printf '%s' "docker run --rm -w /app -v $(pwd):/app ethereum/solc:0.8.16")
$SOLC \
  --overwrite \
  --metadata-hash none \
  --asm-json \
  --storage-layout \
  --bin \
  --bin-runtime \
  --abi \
  --optimize \
  --optimize-runs 4294967295 \
  --userdoc \
  -o "$ROOT"/build/contracts/ \
  $(find "$ROOT"/contracts/ -iname '*.sol' | grep -v templates/)
