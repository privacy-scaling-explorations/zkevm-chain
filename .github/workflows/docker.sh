#!/bin/sh

set -ex

tag=$(git tag --points-at HEAD)

if [ -z "$tag" ]; then
  tag='latest'
fi

docker buildx create --name mybuilder --use || echo 'skip'
docker buildx inspect --bootstrap

for file in docker/*/Dockerfile; do
  path=$(dirname $file)
  ext=${path##*/}
  image="ghcr.io/$GITHUB_REPOSITORY/$ext"
  echo $image:$tag
  # zkevm-circuits/libc has linking problems with linux/arm64
  docker buildx build --push --platform linux/amd64 -t $image:$tag -f $file .
  docker buildx imagetools inspect $image:$tag
done
