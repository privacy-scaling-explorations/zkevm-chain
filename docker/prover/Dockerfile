FROM rust:1.58.1 as builder
WORKDIR /
RUN git clone --depth=1 https://github.com/appliedzkp/zkevm-circuits.git
WORKDIR /zkevm-circuits/prover
ENV RUSTFLAGS='-C target-feature=+crt-static'
RUN cargo build --bins --release --target-dir /target --target $(arch)-unknown-linux-gnu
RUN mv /target/$(arch)-unknown-linux-gnu/release/prover_cmd /target/$(arch)-unknown-linux-gnu/release/gen_params /

FROM scratch
COPY --from=builder /prover_cmd /
COPY --from=builder /gen_params /
