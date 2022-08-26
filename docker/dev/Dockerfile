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
FROM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
RUN apk add --no-cache rustup git musl-dev gcc binutils clang alpine-sdk
ENV CARGO_TARGET_DIR=/target
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=$CARGO_HOME/bin:$PATH
ENV CC=/usr/bin/clang
ENV AR=/usr/bin/ar
COPY rust-toolchain /tmp/rust-toolchain
RUN rustup-init -y --no-modify-path --profile complete --default-toolchain $(cat /tmp/rust-toolchain)
COPY --from=solc /solc /usr/bin/solc
