# syntax=docker/dockerfile:1

FROM alpine:3.15 AS solc
RUN apk update && apk add boost-dev boost-static build-base cmake git
ARG SOLC_VERSION="0.8.18"
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
# Should be alpine like the production images but fails due to
# linkage bug(segfaults of test binaries w/ linked golang code) in rust.
# Use debian until this is resolved.
FROM debian:bookworm-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libc6-dev \
        wget \
        golang \
        pkg-config \
        liblzma-dev \
        procps \
        jq \
        curl \
        git \
        xz-utils \
        time \
        linux-perf \
        libfontconfig-dev
ENV CARGO_TARGET_DIR=/target
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=$CARGO_HOME/bin:$PATH
COPY --link --chmod=444 rust-toolchain /tmp/rust-toolchain
# adapted from official docker-rust
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='bb31eaf643926b2ee9f4d8d6fc0e2835e03c0a60f34d324048aa194f0b29a71c' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='6626b90205d7fe7058754c8e993b7efd91dedc6833a11a225b296b7c2941194f' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='4ccaa7de6b8be1569f6b764acc28e84f5eca342f5162cd5c810891bff7ed7f74' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='34392b53a25c56435b411d3e575b63aab962034dd1409ba405e708610c829607' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.25.2/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile default --default-toolchain $(cat /tmp/rust-toolchain) --default-host ${rustArch}; \
    rm rustup-init;
# set default home to global cache directory
ENV CARGO_HOME=/target/cargo
COPY --from=solc /solc /usr/bin/solc
