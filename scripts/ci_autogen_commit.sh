#!/bin/sh

set -xe

if [ -z "$CI" ]; then
  exit 1
fi

git config --global user.email 'bot@github.action'
git config --global user.name 'github action'
git commit -am 'updates from autogen workflow' || exit 0
git push
