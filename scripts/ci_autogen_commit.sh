#!/bin/sh

set -xe

if [ -z "$CI" ]; then
  exit 1
fi

git config user.email 'github-actions@github.com'
git config user.name github-actions
git commit -am 'updates from autogen workflow' || exit 0
if [ "${GITHUB_REF_PROTECTED}" = "true" ]; then
  git push origin "autogen-$(git rev-parse HEAD)"
else
  git push
fi
