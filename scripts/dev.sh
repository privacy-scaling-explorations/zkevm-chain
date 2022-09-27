#!/bin/sh

set -xe

DOCKER_BUILDKIT=1 docker compose up -d dev
docker compose exec dev bash
