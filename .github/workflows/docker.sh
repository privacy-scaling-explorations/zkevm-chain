#!/bin/sh

set -ex

tag=$(git tag --points-at HEAD)

if [ -z "$tag" ]; then
  tag='latest'
fi

docker buildx create --name mybuilder --use || echo 'skip'
docker buildx inspect --bootstrap

dockerfile="docker/${TARGET}/Dockerfile"
path=$(dirname "${dockerfile}")
ext=${path##*/}
image="ghcr.io/$GITHUB_REPOSITORY/$ext"

docker buildx build \
  --cache-from "type=registry,ref=${image}-ci-cache:latest" \
  --cache-to "type=registry,ref=${image}-ci-cache:latest,mode=max" \
  --push \
  --platform "$PLATFORM" \
  -t "$image:$tag" \
  -f "${dockerfile}" .
docker buildx imagetools inspect "$image:$tag"

docker buildx build \
  --cache-from "type=registry,ref=${image}-ci-cache:latest" \
  --cache-from "type=registry,ref=${image}-ci-cache-secondary:latest" \
  --cache-to "type=registry,ref=${image}-ci-cache-secondary:latest,mode=max" \
  --push \
  -t "$image-ci:$tag" \
  -f "${dockerfile}" .

docker compose build dev
