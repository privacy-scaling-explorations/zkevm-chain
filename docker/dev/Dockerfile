FROM alpine:3.15 AS solc
RUN apk update && apk add boost-dev boost-static build-base cmake git

ARG SOLC_VERSION="0.8.16"
RUN git clone --depth 1 -b v"${SOLC_VERSION}" https://github.com/ethereum/solidity.git
WORKDIR solidity/
RUN \
      touch prerelease.txt && \
      cmake -DCMAKE_BUILD_TYPE=Release -DTESTS=0 -DSOLC_LINK_STATIC=1 && \
      make -j$(nproc) solc && \
      strip solc/solc && \
      mv solc/solc /solc && \
      rm -rf $(pwd)

# developer image
FROM rust:1.58.1
COPY --from=solc /solc /usr/bin/solc
