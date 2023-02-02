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
  --progress plain \
  --cache-from "type=registry,ref=${image}-ci-cache:latest" \
  --cache-to "type=registry,ref=${image}-ci-cache:latest,mode=max" \
  --compress \
  --push \
  --platform "$PLATFORM" \
  -t "$image:$tag" \
  -f "${dockerfile}" .
docker buildx imagetools inspect "$image:$tag"
