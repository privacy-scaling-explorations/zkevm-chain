#!/bin/sh

set -x

if [ ! -d errors/ ]; then
  exit 0
fi

if [ -z "$CI" ]; then
  exit 1
fi

git config --global user.email 'bot@github.action'
git config --global user.name 'github action'
branch=prover-error-$(git rev-parse HEAD)
git checkout -b $branch && git add errors/ && git commit -m 'add prover errors' && git push origin $branch
