#!/bin/sh

set -e

curl \
  -H 'content-type: application/json' \
  -d '{"id":0, "jsonrpc":"2.0","method":"'$1'", "params":['$2']}' \
  "$PROVERD_LOOKUP"
