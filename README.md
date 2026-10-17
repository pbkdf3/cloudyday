# cloudyday

A small SOCKS5 TCP proxy carried over DNS. Applications connect to a local
SOCKS5 port; the client carries their TCP streams inside DNS TXT queries sent
to an ordinary recursive resolver, and the server — the authoritative name
server for a delegated tunnel domain — dials the destinations.

Yes, there are many other tools already named cloudyday.  Don't care.

```text
app -> SOCKS5 (cloudyday client) -> recursive resolver -> cloudyday server -> destination
```

See [DESIGN.md](DESIGN.md) for the protocol.

## Build

Requires a recent stable Rust toolchain (developed with Rust 1.99, edition
2024).

```sh
cargo build --release
```
The binary is `target/release/cloudyday`.

or, (recommended), build static binaries for selected platforms,
the same key is applied to all binaries built, so you can easily
run server and client on different platforms.

```sh
./build.sh
```
The keyed binaries end up as target/[arch]/



### Static Linux binaries (x86_64 and ARM64)

Fully static musl builds run on any Linux distribution of the matching
architecture, with no libc dependency. `.cargo/config.toml` links them with
the `rust-lld` that ships with Rust, so no cross C toolchain is needed, and
either architecture can be built from the other:

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl # only needed once

cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

The binaries are `target/<target>/release/cloudyday`.

### macOS binary (Apple Silicon)

macOS has no fully static executables: every program links `libSystem`
dynamically. The macOS build depends only on libraries in `/usr/lib` that ship
with the OS, and needs macOS 13 or later. It is cross-built from Linux with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild), which uses
[zig](https://ziglang.org/) as the linker, so no Xcode or macOS SDK is needed:

```sh
rustup target add aarch64-apple-darwin   # only needed once
cargo install --locked cargo-zigbuild    # only needed once; zig must be on PATH

cargo zigbuild --release --target aarch64-apple-darwin
```

A warning that `xcrun` could not find the SDK is expected and harmless. The
linker gives the binary an ad-hoc code signature, which Apple Silicon requires.

## Set up

You need a server with a public IP whose UDP port 53 is reachable, and a
domain you control.

1. **Delegate a subdomain to the server.** In the parent zone (here
   `example.com`), add an NS record for the tunnel domain and a glue record
   for the name server:

   ```text
   t.example.com.      IN NS  ns-t.example.com.
   ns-t.example.com.   IN A   203.0.113.10    ; the server's public IP
   ```
   **If using cloudflare, make sure to toggle "DNS Proxy" OFF whenever it 
   is an option when adding the records.  Otherwise this will not work.**

   Keep the tunnel domain short: every byte of it reduces the payload each
   query can carry. Overly long domains are rejected at startup.

2. **Key and share the executable (Linux).** After building, use `rekey.py` to
   append a 32-byte random key to the executable:

   ```sh
   cp target/release/cloudyday ./cloudyday
   python3 rekey.py rekey ./cloudyday
   ```

   Run the script once with every architecture-specific binary if they must
   share a key; one invocation applies the same new key to every named file:

   ```sh
   python3 rekey.py rekey ./cloudyday-x86_64 ./cloudyday-aarch64
   ```
   Securely copy the appropriate keyed executable to each client and keep all
   copies private. Both server and client refuse to start without an embedded
   key and tell you to add one with `rekey.py`.

   Key the finished binary after building and stripping, and before applying 
   `setcap`; modifying an executable can discard its trailer or file capabilities.


## Run

### Server

```sh
cloudyday server --domain t.example.com
```

This reads the embedded key and exits with instructions to run `rekey.py` if
none is present.

It listens on `0.0.0.0:53` by default (`--listen` to change). Binding port 53
needs privileges; rather than running as root you can grant the capability
after adding the key:

```sh
python3 rekey.py rekey ./cloudyday
sudo setcap cap_net_bind_service=+ep ./cloudyday
```

Reapply the capability if key rotation removes it.

By default the server refuses loopback, private, link-local (including cloud
metadata), CGNAT, multicast, and other internal destinations, plus its own
addresses — also when a hostname resolves to one. Pass
`--allow-private-destinations` to reach services on the server's own network.

The server answers other queries in its zone as a minimal authoritative
server (SOA at the apex, NODATA elsewhere) and refuses names outside it. It
never forwards queries.

### Client

```sh
cloudyday client --domain t.example.com --resolver 1.1.1.1:53
```

Run a securely transferred copy of the server's keyed executable; the working
directory does not matter.
`--resolver` is any recursive resolver that can reach your server. The SOCKS5
proxy listens on `127.0.0.1:1080` by default (`--listen` to change; it has no
authentication, so a non-loopback address prints a warning).

Point applications at the SOCKS5 proxy. Use remote name resolution so the
server resolves hostnames:

```sh
curl -x socks5h://127.0.0.1:1080 https://ip.me/
```

Only SOCKS5 CONNECT (TCP) is supported.  UDP forwarding is not currently supported.

### Reverse SOCKS (optional, server-controlled)

To reach destinations from the **client's** network, enable a SOCKS5 listener
on the server:

```sh
cloudyday server --domain t.example.com --reverse-socks
cloudyday client --domain t.example.com --resolver 1.1.1.1:53
# On the server, once the client has connected:
curl --socks5-hostname 127.0.0.1:1080 https://ip.me/
```

```text
app -> SOCKS5 (cloudyday server) -> DNS tunnel -> cloudyday client -> destination
```

`--reverse-socks` defaults to `127.0.0.1:1080`; supply an address to change it,
for example `--reverse-socks 127.0.0.1:2080`. The listener opens only after a
client establishes a session and closes when that session expires. A bind
failure stops the server with an error. The normal forward proxy remains
available (use different SOCKS ports when running both sides on one host).


### Encryption and authentication

A pre-shared key is used for authentication.  The protocol uses HMAC-SHA256 and nonces to securely authenticate without leaking the key.

HKDF-SHA256 is used to generate an ephemeral session key, chacha20 is used as a symmetric cipher.  

### Logging

`-v` enables debug logs, `-vv` trace, and `-q` warnings only. `RUST_LOG`
overrides these when set. Logs never include key material or tunneled data.

## Trying it locally

Both sides can run on one machine, with the client talking to the server
directly instead of through a resolver:

```sh
python3 rekey.py rekey ./cloudyday
./cloudyday server --domain t.example.com --listen 127.0.0.1:5353 \
    --allow-private-destinations &
sleep 1
./cloudyday client --domain t.example.com --resolver 127.0.0.1:5353 \
    --listen 127.0.0.1:1080 &
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

## Tests

```sh
cargo test                       # unit tests, simulations, real-socket end-to-end
python3 tools/gen_vectors.py --check   # DESIGN.md Appendix A vectors are current
cargo test --release --test sim -- --ignored --nocapture   # throughput probe
```

## Limitations

- Throughput is modest: tens of KB/s, depending on resolver round-trip time.
- With no forward streams, the client polls once per second to discover
  reverse SOCKS opens. With idle forward streams it backs off to every 15
  seconds, so new reverse opens or server data can wait that long.
- Only one resolver, one tunnel domain, and TCP via SOCKS5 CONNECT. No UDP,
  IPv6-only setups are untested, and it is not wire-compatible with other DNS
  tunnels.
