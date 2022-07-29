FROM --platform=$BUILDPLATFORM rust:1.58.1-alpine AS builder
RUN apk add --no-cache git musl-dev

ARG TARGETPLATFORM
RUN \
  case $TARGETPLATFORM in \
  'linux/amd64') arch=x86_64 ;; \
  'linux/arm64') arch=aarch64 ;; \
  esac; \
  printf "$arch-unknown-linux-musl" > /tmp/target;

COPY coordinator/ /build
WORKDIR /build
RUN rustup target add $(cat /tmp/target)
RUN cargo fetch --target $(cat /tmp/target)
ENV RUSTFLAGS='-C linker=rust-lld'
RUN cargo build --bin coordinator --release --target-dir /target --target $(cat /tmp/target)

FROM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
COPY --from=builder /target/*-unknown-linux-musl/release/coordinator /
ENTRYPOINT ["/coordinator"]
