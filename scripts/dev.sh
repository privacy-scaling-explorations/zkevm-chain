#!/bin/sh

set -xe
trap 'docker compose down --timeout 1' exit

DOCKER_BUILDKIT=1 docker compose run --service-ports --use-aliases --rm dev -i
