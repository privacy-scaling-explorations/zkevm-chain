FROM --platform=$BUILDPLATFORM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c AS builder
RUN apk add --no-cache rustup git musl-dev gcc binutils clang go
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=$CARGO_HOME/bin:$PATH
ENV RUSTFLAGS='-C linker=rust-lld'
ENV CC=/usr/bin/clang
ENV AR=/usr/bin/ar

ARG TARGETPLATFORM
RUN \
  case $TARGETPLATFORM in \
  'linux/amd64') arch=x86_64 ;; \
  'linux/arm64') arch=aarch64 ;; \
  esac; \
  printf "$arch-unknown-linux-musl" > /tmp/target;

WORKDIR /target/src
COPY rust-toolchain .
RUN rustup-init -y --no-modify-path --profile minimal --default-toolchain $(cat rust-toolchain) --target $(cat /tmp/target)
# trigger fetch of crates index
RUN cargo search --limit 0

COPY . .
RUN cargo build --locked --bin prover_rpcd --release --target-dir /target --target $(cat /tmp/target) && \
      mv /target/*-unknown-linux-musl/release/prover_rpcd / && rm -rf /target

FROM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
ENTRYPOINT ["/prover_rpcd"]
COPY --from=builder /prover_rpcd /
