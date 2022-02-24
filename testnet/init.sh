#!/bin/sh

set -e

GETH_ARGS='--config=/host/geth.toml'

if [[ ! -e /root/.ethereum/geth ]]; then
  echo 'init chain'
  cat $1 | sed "s/MINER_ADDRESS/$MINER_ADDRESS/g" > $2
  geth $GETH_ARGS init $2
  geth $GETH_ARGS --exec 'personal.importRawKey("'$MINER_PRIV_KEY'", null)' console
fi

shift 2
exec geth $GETH_ARGS $@
