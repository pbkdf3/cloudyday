#!/bin/bash

rm -rf target/*
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl

# macOS (Apple Silicon) needs cargo-zigbuild and zig on PATH
cargo zigbuild --release --target aarch64-apple-darwin

# key all binaries with the same random key
./rekey.py rekey target/x86_64-unknown-linux-musl/release/cloudyday target/aarch64-unknown-linux-musl/release/cloudyday target/aarch64-apple-darwin/release/cloudyday

