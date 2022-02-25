#!/bin/sh

set -ex

tag=$(git tag --points-at HEAD)

if [ -z "$tag" ]; then
  tag='latest'
fi

base=$(pwd)

docker buildx create --name mybuilder --use || echo 'skip'
docker buildx inspect --bootstrap

for file in docker/*/Dockerfile; do
  cd $(dirname $file)
  ext=${PWD##*/}
  image="ghcr.io/$GITHUB_REPOSITORY/$ext"
  echo $image:$tag
  docker buildx build --platform linux/amd64,linux/arm64 -t $image:$tag --push .
  docker buildx imagetools inspect $image:$tag
  cd $base
done
