#!/bin/sh

set -e

GETH_ARGS='--config=/host/geth.toml'

if [[ ! -e /root/.ethereum/geth ]]; then
  echo 'init chain'
  gen=/host/genesis-generated.json
  cat /host/genesis-template.json | sed "s/MINER_ADDRESS/$MINER_ADDRESS/g" > $gen
  geth $GETH_ARGS init $gen
  geth $GETH_ARGS --exec 'personal.importRawKey("'$MINER_PRIV_KEY'", null)' console
fi

exec geth $GETH_ARGS $@
