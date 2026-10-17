#!/bin/bash

cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl


tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT

openssl rand 32 >"$tmp"
printf '\x29\xd9\x31\xf3\x21\xc2\xdf\xe2\xd1\x45\x98\x63\xbc\x8f\xd3\x5b\xd0\x92\x63\x86\xc0\x7d\x02\xa8\x55\x98\xb5\x0a\xba\xb0\x58\xd8' >> $tmp

cat $tmp >> target/x86_64-unknown-linux-musl/release/cloudyday
cat $tmp >> target/aarch64-unknown-linux-musl/release/cloudyday

