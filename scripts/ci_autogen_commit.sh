#!/bin/sh

set -xe

if [ -z "$CI" ]; then
  exit 1
fi

./scripts/patch_genesis.mjs
git config --global user.email 'bot@github.action'
git config --global user.name 'github action'
git commit -am 'updates from autogen workflow'
git push
