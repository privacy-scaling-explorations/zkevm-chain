#!/bin/sh
# usage rpc_url block_number
url=$1
blockNumber=$2

set -e

rpc() {
  curl \
    --silent \
    -H 'content-type: application/json' \
    -d '{"id":0, "jsonrpc":"2.0","method":"'$1'", "params":['$2']}' \
    $url
}

hex() {
  printf '0x%x' $1
}

blockHex=$(hex $blockNumber)

echo '### block.json'
rpc 'eth_getBlockByNumber' '"'$blockHex'",true' | jq '.result' > block.json

echo '### prestate.json'
rpc 'debug_traceBlockByNumber' '"'$blockHex'",{"tracer":"prestateTracer"}' | jq '.result' > prestate.json

echo '### block_hashes.json'
stop=$(($blockNumber - 1))
start=$(($stop - 255))
tmp='['
for num in $(seq $start $stop); do
  if [ $num -lt 0 ]; then
    tmp=$tmp'"0x0000000000000000000000000000000000000000000000000000000000000000",'
    continue
  fi
  blockHex=$(hex $num)
  hash=$(rpc 'eth_getHeaderByNumber' '"'$blockHex'"' | jq '.result.hash')
  tmp=$tmp$hash','
done
tmp=$(printf -- $tmp | head -c -1)
tmp="$tmp]"
echo "$tmp" | jq > block_hashes.json

