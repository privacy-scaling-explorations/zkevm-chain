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
RUN git clone --depth=1 https://github.com/appliedzkp/zkevm-circuits.git
WORKDIR /zkevm-circuits
RUN cargo build --bins --release --target-dir /target --package prover
RUN mv /target/release/prover_cmd /target/release/gen_params /

COPY coordinator/ /build
WORKDIR /build
RUN cargo build --bins --release --target-dir /target
RUN mv /target/release/coordinator /

FROM scratch
COPY --from=builder /prover_cmd /
COPY --from=builder /gen_params /
COPY --from=builder /coordinator /
ENTRYPOINT ["/coordinator"]
