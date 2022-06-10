#!/bin/sh

set -e

DEFAULT_GETH_ARGS=''
GENESIS_GENERATED='/root/genesis.json'
GENESIS_TEMPLATE="/templates/$GENESIS.json"

if [[ ! -e /root/.ethereum/geth ]]; then
  echo 'init chain'
  cat "$GENESIS_TEMPLATE" | sed "s/MINER_ADDRESS/$MINER_ADDRESS/g" > $GENESIS_GENERATED
  geth $DEFAULT_GETH_ARGS init $GENESIS_GENERATED
fi

if [[ ! -z $MINER_PRIV_KEY ]]; then
  geth $DEFAULT_GETH_ARGS --exec 'try { personal.importRawKey("'$MINER_PRIV_KEY'", null) } catch (e) { if (e.message !== "account already exists") { throw e; } }' console
fi

if [[ ! -z $BOOTNODE ]]; then
  geth $DEFAULT_GETH_ARGS --exec 'admin.addTrustedPeer("'$BOOTNODE'")' console
  DEFAULT_GETH_ARGS="$DEFAULT_GETH_ARGS --bootnodes $BOOTNODE"
fi

exec geth $DEFAULT_GETH_ARGS $@
