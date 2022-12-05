#!/bin/sh

set -x

if [ ! -d errors/ ]; then
  exit 0
fi

if [ -z "$CI" ]; then
  exit 1
fi

sudo chown -R $(id -nu) errors/

git config user.email 'github-actions@github.com'
git config user.name github-actions
name=${1:-unknown}
branch=prover-error-"$1"-$(git rev-parse HEAD)
git checkout -b $branch && git add errors/ && git commit -m 'add prover errors' && git push origin $branch

git reset --hard HEAD^
# exit with error to signal prover failure
exit 1
