FROM rust:1.58.1 as builder
WORKDIR /
RUN git clone -b feat/prover --depth=1 https://github.com/pinkiebell/zkevm-circuits.git
WORKDIR /zkevm-circuits/prover
RUN rm ../rust-toolchain
ENV RUSTFLAGS='-C target-feature=+crt-static'
ARG TARGETARCH
RUN cargo build --bins --release --target-dir /target --target ${TARGETARCH:-$(arch)}-unknown-linux-gnu
RUN mv /target/${TARGETARCH:-$(arch)}-unknown-linux-gnu/release/prover_cmd /target/${TARGETARCH:-$(arch)}-unknown-linux-gnu/release/gen_params /

FROM scratch
COPY --from=builder /prover_cmd /
COPY --from=builder /gen_params /
