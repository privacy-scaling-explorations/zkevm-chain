FROM rust:1.58.1-alpine as builder
RUN apk add --no-cache git musl-dev

# some build scripts have a problem to choose a compiler
ENV CC=/usr/bin/gcc
ENV AR=/usr/bin/ar
# Re: error: ... contains a compressed section, but zlib is not available
ENV CFLAGS='-Wa,--compress-debug-sections=none -Wl,--compress-debug-sections=none'
# fixes linking, using the native linker will result in complaining about missing and/or duplicate symbols
ENV RUSTFLAGS='-C linker=rust-lld -Lnative=/usr/lib -Lnative=/usr/lib/gcc/aarch64-alpine-linux-musl/10.3.1/ -Lnative=/usr/lib/gcc/x86_64-alpine-linux-musl/10.3.1/'

COPY coordinator/ /build
WORKDIR /build
RUN cargo build --bins --release --target-dir /target

FROM alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
COPY --from=builder /target/release/coordinator /
ENTRYPOINT ["/coordinator"]
