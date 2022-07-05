FROM ghcr.io/privacy-scaling-explorations/zkevm-chain/params@sha256:a38ef4d64a38e9137b06f32e7121d22a5c9de6034195c0c133e53acec4499152 AS params

FROM rust:1.58.1-alpine as builder
RUN apk add --no-cache git musl-dev

# some build scripts have a problem to choose a compiler
ENV CC=/usr/bin/gcc
ENV AR=/usr/bin/ar
# Re: error: ... contains a compressed section, but zlib is not available
ENV CFLAGS='-Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none'
# fixes linking, using the native linker will result in complaining about missing and/or duplicate symbols
ENV RUSTFLAGS='-C linker=rust-lld -Lnative=/usr/lib -Lnative=/usr/lib/gcc/aarch64-alpine-linux-musl/10.3.1/ -Lnative=/usr/lib/gcc/x86_64-alpine-linux-musl/10.3.1/'

WORKDIR /
#RUN git clone --depth=1 https://github.com/privacy-scaling-explorations/zkevm-circuits.git
RUN git clone --depth=1 -b v2022-07-05 https://github.com/pinkiebell/zkevm-circuits.git
WORKDIR /zkevm-circuits
RUN cargo build --bins --release --target-dir /target --package prover

FROM scratch
COPY --from=builder /target/release/prover_rpcd /
COPY --from=builder /target/release/prover_cmd /
COPY --from=builder /target/release/gen_params /
COPY --from=params /testnet /testnet
ENTRYPOINT ["/prover_rpcd"]
