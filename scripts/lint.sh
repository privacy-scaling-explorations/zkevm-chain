#!/bin/sh

cargo fmt --all
cargo clippy --all-features --all-targets
