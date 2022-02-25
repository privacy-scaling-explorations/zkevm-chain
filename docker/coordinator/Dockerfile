FROM rust:1.58.1 as builder
ENV RUSTFLAGS='-C target-feature=+crt-static'

WORKDIR /
RUN git clone --depth=1 https://github.com/appliedzkp/zkevm-circuits.git
WORKDIR /zkevm-circuits/prover
RUN cargo build --bins --release --target-dir /target --target $(arch)-unknown-linux-gnu
RUN mv /target/$(arch)-unknown-linux-gnu/release/prover_cmd /target/$(arch)-unknown-linux-gnu/release/gen_params /

COPY coordinator/ /build
WORKDIR /build
RUN cargo build --bins --release --target-dir /target --target $(arch)-unknown-linux-gnu
RUN mv /target/$(arch)-unknown-linux-gnu/release/coordinator /

FROM scratch
COPY --from=builder /prover_cmd /
COPY --from=builder /gen_params /
COPY --from=builder /coordinator /
#TODO: dns resolution fails for the coordinator binary without these
COPY --from=builder /lib /lib
ENTRYPOINT ["/coordinator"]
