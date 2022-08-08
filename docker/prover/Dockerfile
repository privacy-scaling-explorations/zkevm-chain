FROM --platform=$BUILDPLATFORM ghcr.io/privacy-scaling-explorations/zkevm-chain/params@sha256:a38ef4d64a38e9137b06f32e7121d22a5c9de6034195c0c133e53acec4499152 AS params

FROM --platform=$BUILDPLATFORM rust:1.58.1-alpine AS builder
RUN apk add --no-cache git musl-dev clang

ARG TARGETPLATFORM
RUN \
  case $TARGETPLATFORM in \
  'linux/amd64') arch=x86_64 ;; \
  'linux/arm64') arch=aarch64 ;; \
  esac; \
  printf "$arch-unknown-linux-musl" > /tmp/target;

WORKDIR /
RUN git clone --depth 1 -b v2022-08-08 https://github.com/pinkiebell/zkevm-circuits.git

WORKDIR /zkevm-circuits/prover
RUN rustup target add $(cat /tmp/target)
RUN cargo fetch --target $(cat /tmp/target)
ENV CC=/usr/bin/clang
ENV AR=/usr/bin/ar
ENV RUSTFLAGS='-C linker=rust-lld'
RUN cargo build --bin prover_rpcd --release --target-dir /target --target $(cat /tmp/target)

FROM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
COPY --from=builder /target/*-unknown-linux-musl/release/prover_rpcd /
COPY --from=params /testnet /testnet
ENTRYPOINT ["/prover_rpcd"]
