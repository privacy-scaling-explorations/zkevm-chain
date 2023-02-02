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
# Should be alpine like the production images but fails due to
# linkage bug(segfaults of test binaries w/ linked golang code) in rust.
# Use debian until this is resolved.
FROM debian:bookworm-slim
COPY --from=solc /solc /usr/bin/solc
ENV CARGO_TARGET_DIR=/target
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=$CARGO_HOME/bin:$PATH
COPY --chmod=444 rust-toolchain /tmp/rust-toolchain
# adapted from official docker-rust
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
        libfontconfig-dev \
        ; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "${dpkgArch##*-}" in \
        amd64) rustArch='x86_64-unknown-linux-gnu'; rustupSha256='5cc9ffd1026e82e7fb2eec2121ad71f4b0f044e88bca39207b3f6b769aaa799c' ;; \
        armhf) rustArch='armv7-unknown-linux-gnueabihf'; rustupSha256='48c5ecfd1409da93164af20cf4ac2c6f00688b15eb6ba65047f654060c844d85' ;; \
        arm64) rustArch='aarch64-unknown-linux-gnu'; rustupSha256='e189948e396d47254103a49c987e7fb0e5dd8e34b200aa4481ecc4b8e41fb929' ;; \
        i386) rustArch='i686-unknown-linux-gnu'; rustupSha256='0e0be29c560ad958ba52fcf06b3ea04435cb3cd674fbe11ce7d954093b9504fd' ;; \
        *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.25.1/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile default --default-toolchain $(cat /tmp/rust-toolchain) --default-host ${rustArch}; \
    rm rustup-init;
# set default home to global cache directory
ENV CARGO_HOME=/target/cargo
