#!/bin/bash

rm -rf target/*
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
#python3 rekey.py target/x86_64-unknown-linux-musl/release/cloudyday target/aarch64-unknown-linux-musl/release/cloudyday
