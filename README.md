# Cloudyday

A small SOCKS5 TCP proxy carried over DNS. Applications connect to a local
SOCKS5 port; the client carries their TCP streams inside DNS TXT queries sent
to an ordinary recursive resolver, and the server — the authoritative name
server for a delegated tunnel domain — dials the destinations.

```text
app -> SOCKS5 (client) -> recursive resolver -> cloudyday server -> destination
```

See [DESIGN.md](DESIGN.md) for the protocol.

> **Security warning.** The handshake authenticates both peers using a shared
> secret. Session traffic uses **plain ChaCha20 without authentication tags**:
> active attackers can modify ciphertext or forge public session errors. There
> is no forward secrecy, and routing metadata remains visible. Use TLS inside
> the tunnel for sensitive traffic. SOCKS listeners themselves have no authentication.

## Build

Requires a recent stable Rust toolchain (developed with Rust 1.99, edition
2024).

```sh
cargo build --release
```

The binary is `target/release/cloudyday`.

### Static Linux binaries (x86_64 and ARM64)

Fully static musl builds run on any Linux distribution of the matching
architecture, with no libc dependency. `.cargo/config.toml` links them with
the `rust-lld` that ships with Rust, so no cross C toolchain is needed, and
either architecture can be built from the other:

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

The binaries are `target/<target>/release/cloudyday`.

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

   Keep the tunnel domain short: every byte of it reduces the payload each
   query can carry. Overly long domains are rejected at startup.

2. **Initialize and share the executable (Linux).** On its first start the
   server generates 32 random bytes and embeds them in its executable's
   trailer. Later starts reuse that key. Securely copy the resulting executable
   to the client (with a matching CPU architecture), and keep both copies private.
   The client never generates a key and refuses an executable without a trailer.
   There are no key files or `--key-file` / `--xor-key-file` options.

   To initialize without starting the server, or to **rotate** an existing key:

   ```sh
   cp target/release/cloudyday ./cloudyday
   ./cloudyday server --genkey
   ```

   `--genkey` always generates a new key and exits; no domain or sockets are
   required. After rotation, restart the server and securely redistribute the
   executable to every client. Already running processes retain their old key.

   Initialization and rotation require write permission on the executable's
   directory. The program atomically replaces its executable with a private
   copy (mode 0700); it does not write to the running inode. File capabilities,
   ownership, and other extended attributes are not preserved. Initialize
   **before** applying `setcap`. Normal starts with an existing key need no
   write permission. This feature requires Linux with `/proc` mounted.

   **Anyone who can read the executable can extract the secret.** Protect it
   like a key file, including during transfer and backup. Finish building and
   stripping before initialization: rebuilding or processing the binary may
   discard the trailer. Protocol v2 remains incompatible with the old XOR
   protocol; update both endpoints rather than reusing old XOR keys.

## Run

### Server

```sh
cloudyday server --domain t.example.com
```

This reuses the embedded key, or generates and embeds one if absent.

It listens on `0.0.0.0:53` by default (`--listen` to change). Binding port 53
needs privileges; rather than running as root you can grant the capability
**after** initializing the key:

```sh
./cloudyday server --genkey
sudo setcap cap_net_bind_service=+ep ./cloudyday
```

Key rotation replaces the file and drops this capability; reapply it afterward.

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
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

Only SOCKS5 CONNECT (TCP) is supported.

### Reverse SOCKS (optional, server-controlled)

To reach destinations from the **client's** network, enable a SOCKS5 listener
on the server:

```sh
cloudyday server --domain t.example.com --reverse-socks
cloudyday client --domain t.example.com --resolver 1.1.1.1:53
# On the server, once the client has connected:
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

```text
app -> SOCKS5 (server) -> DNS tunnel -> cloudyday client -> destination
```

`--reverse-socks` defaults to `127.0.0.1:1080`; supply an address to change it,
for example `--reverse-socks 127.0.0.1:2080`. The listener opens only after a
client establishes a session and closes when that session expires. A bind
failure stops the server with an error. The normal forward proxy remains
available (use different SOCKS ports when running both sides on one host).

Only one client is allowed while reverse SOCKS is enabled: **the newest
established session wins**, closing the previous client's tunnel connections.
The displaced client stops reconnecting automatically; restart it to reclaim
the proxy. Handshake retransmissions do not count as a new connection.

Clients connect automatically at startup and always support reverse SOCKS,
without a client-side flag. Hostnames are resolved on the client. Reverse
SOCKS intentionally allows its loopback and private-network destinations;
`--allow-private-destinations` still controls only forward dialing on the
server. **Trust the server before connecting a client:** it can access the
client's network. The shared secret authenticates the tunnel handshake,
not individual packets or local SOCKS users. Use updated binaries on both sides.

### Encryption and authentication

HELLO/CHALLENGE exchange fresh nonces and a server cookie. COOKIE_ECHO carries
an HMAC-SHA256 client proof; ACCEPT carries a server proof bound to the assigned
session. HKDF-SHA256 derives independent keys for each direction from the shared
secret and handshake transcript. Proofs are public, but are not encryption keys.

Established envelopes retain their existing nine-byte routing prefix and
ChaCha20-encrypt everything after it, including stream opening records and data.
The session and exchange IDs determine the nonce: **no extra nonce bytes,
no tag, and zero additional per-envelope bytes**. Handshakes and marked session
errors are public. Duplicate queries replay cached ciphertext; counters never
wrap. Authentication is checked before allocating a session or replacing a
reverse-SOCKS owner. It is not checked per packet: tampering remains possible.

### Logging

`-v` enables debug logs, `-vv` trace, and `-q` warnings only. `RUST_LOG`
overrides these when set. Logs never include key material or tunneled data.

## Trying it locally

Both sides can run on one machine, with the client talking to the server
directly instead of through a resolver:

```sh
cloudyday server --domain t.example.com --listen 127.0.0.1:5353 \
    --allow-private-destinations &
sleep 1   # the server embeds a key; the client launches the replaced executable
cloudyday client --domain t.example.com --resolver 127.0.0.1:5353 \
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
