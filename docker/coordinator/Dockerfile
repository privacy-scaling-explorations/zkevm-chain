FROM rust:1.58.1-alpine as builder
RUN apk add --no-cache git musl-dev
ENV RUSTFLAGS='-C target-feature=+crt-static'

WORKDIR /
RUN git clone --depth=1 https://github.com/appliedzkp/zkevm-circuits.git
WORKDIR /zkevm-circuits
RUN cargo build --bins --release --target-dir /target --target $(arch)-unknown-linux-musl --package prover
RUN mv /target/$(arch)-unknown-linux-musl/release/prover_cmd /target/$(arch)-unknown-linux-musl/release/gen_params /

COPY coordinator/ /build
WORKDIR /build
RUN cargo build --bins --release --target-dir /target --target $(arch)-unknown-linux-musl
RUN mv /target/$(arch)-unknown-linux-musl/release/coordinator /

FROM scratch
COPY --from=builder /prover_cmd /
COPY --from=builder /gen_params /
COPY --from=builder /coordinator /
#TODO: dns resolution fails for the coordinator binary without these (only with glibc)
#COPY --from=builder /lib /lib
ENTRYPOINT ["/coordinator"]
