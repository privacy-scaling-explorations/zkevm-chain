#!/bin/sh

set -xe

cargo test --release --features autogen -- --nocapture $@
