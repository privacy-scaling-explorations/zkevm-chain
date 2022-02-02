#!/bin/sh

set -e

GETH_ARGS='--config=/host/geth.toml'

if [[ ! -e /root/.ethereum/geth ]]; then
  echo 'init chain'
  cat /host/genesis.json | sed "s/df08f82de32b8d460adbe8d72043e3a7e25a3b39/$MINER_ADDRESS/g" > genesis.json
  geth $GETH_ARGS init genesis.json
  geth $GETH_ARGS --exec 'personal.importRawKey("'$MINER_PRIV_KEY'", null)' console
fi

exec geth $GETH_ARGS --mine
