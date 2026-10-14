# Cloudyday design

Status: v1 design, implemented in `src/`. Internal limits and timing
constants below are starting points to validate in tests, not user-facing knobs.

## 1. Goal and scope

A small, understandable Rust SOCKS5 TCP proxy carried over DNS. Inspired by
MasterDnsVPN's per-stream selective-repeat ARQ, but not wire-compatible with it.

```text
Application -> local SOCKS5 -> DNS queries -> recursive resolver
            -> authoritative Cloudyday server -> destination TCP
Application <- local SOCKS5 <- DNS responses <- recursive resolver
            <- authoritative Cloudyday server <- destination TCP
```

One executable, with `client` and `server` subcommands:

- SOCKS5 CONNECT only; IPv4, IPv6, and domain-name destinations.
- Resolve domain-name destinations on the server.
- One client resolver, one delegated tunnel domain, multiple TCP connections.
- Required repeating-key XOR obfuscation; no plaintext mode.
- No client/server authentication or envelope integrity protection.
- Server refuses loopback, private, and other internal destinations by default.
- No TUN, SOCKS4, SOCKS UDP/BIND, local DNS listener, compression, multipath,
  resolver discovery, upstream proxy chaining, or MasterDnsVPN compatibility.

## 2. CLI and operational defaults

```sh
cloudyday server --domain t.example.com --listen 0.0.0.0:53 --xor-key-file /path/to/key
cloudyday client --domain t.example.com --resolver 192.0.2.53:53 --xor-key-file /path/to/key

# Both sides require the same nonempty XOR key file.

# Server only, off by default:
# --allow-private-destinations
```

Client SOCKS listen address defaults to `127.0.0.1:1080`, overridable with
`--listen`. No local SOCKS authentication in v1; binding to a non-loopback
address produces a warning. Verbosity is the only other initial CLI setting.

By default the server refuses destinations in loopback, unspecified,
link-local (including cloud metadata such as `169.254.169.254`), RFC 1918,
CGNAT `100.64.0.0/10`, ULA `fc00::/7`, multicast, broadcast, and reserved
ranges, plus addresses assigned to the server's own interfaces. Normalize
IPv4-mapped and IPv4-compatible IPv6 forms before checking. Check every address
after name resolution and immediately before dialing, so a hostile DNS answer
cannot rebind a public name to an internal address. Refused destinations get
SOCKS status `0x02` (connection not allowed by ruleset).
`--allow-private-destinations` disables this filter for deliberate use, such as
reaching services on the server's own network.

No configuration file or exposed ARQ/worker/queue tuning in v1. Read the required
XOR key file as nonempty raw bytes, without trimming. Reject missing or empty
keys and other invalid configuration at startup; never log key material,
cookies, or tunneled content.

The domain must be delegated to the server, whose UDP DNS port must be reachable
by the resolver. This is a TCP proxy, not an IP VPN. The server is not a generic
recursive DNS service and never forwards arbitrary incoming DNS questions; it
answers non-tunnel questions as a minimal authoritative server (§7.4).

Always warn at startup that the tunnel has no authentication and XOR is not
access control. Treat the server as an open proxy: an observer can recover a
repeating key and forge traffic. Apply resource limits. XOR is obfuscation, not
secure encryption; users needing confidentiality should use application-level
TLS. Application TLS does not restrict who can use the proxy.

## 3. Rust architecture

Use Tokio for networking, bounded channels, and cancellation. Suggested modules:

| Module | Responsibility |
| --- | --- |
| `cli` | Arguments, key loading, startup, logging |
| `wire` | Bounded binary parsing, framing, XOR, server-cookie HMAC |
| `dns` | DNS encoding/parsing, query tracking, payload budgets, non-tunnel answers |
| `arq` | Pure selective-repeat state machine and retransmission deadlines |
| `session` | Handshake, stream lifecycle, flow control, scheduling, polling |
| `socks` | SOCKS5 negotiation and TCP bridging |

Keep protocol state separate from socket I/O. An ARQ instance accepts input
frames and explicit timestamps, and emits outbound frames and delivery events.
It does not own sockets, spawn tasks, or call the clock itself.

A session task owns its mutable protocol state. Socket readers/writers report
through bounded channels; slow TCP writes must not block the session task.
Avoid shared mutable ARQ state behind locks. Use one session-level deadline timer
rather than a task or periodic timer per packet.

Use an established DNS wire library rather than writing a general DNS parser.
Keep dependencies modest: Tokio, clap, bytes, tracing, a DNS wire library,
base32 support, OS randomness, and HMAC-SHA256 support for stateless server
cookies only (not peer authentication or envelope tags).

## 4. Wire format sketch

All integers are network byte order. Parsing checks every length before reading
or allocating. The protocol has a fixed version; unsupported versions fail
explicitly rather than negotiating compatibility.

Every byte of envelope header is paid on every DNS exchange, and upload queries
carry only about 150 envelope bytes (§7.2), so the header is deliberately
compact. An envelope contains:

```text
client -> server:
  ver_flags: u8 | session_id: u32 | exchange_id: u32 | rx_lag: u8
  frames...

server -> client:
  ver_flags: u8 | session_id: u32 | exchange_id: u32
  frames...

ver_flags = version: 3 bits (high) | flags: 5 bits (low)
frame     = kind: u8 | length: u8 | body: [u8; length]
```

Flags:

| Flag | Meaning |
| --- | --- |
| MORE_PENDING | Server to client: more frames are queued for this session |

Frames run until the end of the envelope; there is no frame count or
authentication tag. An envelope with no frames is valid: from the client it is a
poll or keepalive, and from the server it means nothing is pending. Every
envelope is XORed before DNS encoding (§8).

Handshake envelopes use session ID zero until ACCEPT. Session IDs are random
nonzero 32-bit values; they identify state, not credentials. The client assigns
a fresh monotonically increasing exchange ID to every DNS attempt, including
polls and retransmissions. A response echoes the exchange ID of its question.
`rx_lag` is the current exchange ID minus the highest exchange ID whose response
the client has received in this session, saturating at 255; it lets the server
detect lost responses (§5). The value 255 also represents no response received
and supplies no positive evidence of response delivery.

Stream IDs are client-assigned monotonically increasing `u32` values, never
reused within a session. Each direction has independent `u32` sequence numbers.
Do not wrap counters: establish a new session or reset an exhausted stream or
exchange counter.

Core frames:

| Frame | Body | Meaning |
| --- | --- | --- |
| HELLO / CHALLENGE / COOKIE_ECHO / ACCEPT | see §8 | Session establishment |
| SEGMENT | stream: u32, seq: u32, payload | Reliable stream bytes |
| FIN | stream: u32, seq: u32 | Reliable sequenced end of one direction |
| STREAM_ACK | stream: u32, next_expected: u32, sack: u32, credit_delta: u16 | Receive state and flow control for one direction of one stream |
| RESET | stream: u32, reason: u8 | Abort a stream |
| SESSION_ERROR | reason: u8 | Server to client: unknown session, unsupported version, or server busy |

STREAM_ACK replaces separate ACK, NACK, and CREDIT frames:

- `next_expected` is cumulative: every sequence below it has been received and
  retained.
- `sack` bit `i` is set when sequence `next_expected + 1 + i` has been received
  and retained. Clear bits below the highest set bit are the missing
  sequences, so no separate NACK is needed. A 32-bit map covers the whole
  32-frame receive window.
- `credit_delta` gives the exclusive credit limit as
  `next_expected + credit_delta`. The limit is never below `next_expected`,
  including after a credit-free FIN (§5, A.5).

Each STREAM_ACK fully describes the receiver's current state, so a lost one is
repaired by the next one, and ACK, NACK, and CREDIT information cannot drift
apart. Responses may be reordered: merge ACKs monotonically, never lowering
the cumulative acknowledgement or credit limit, and never forgetting previously
SACKed sequences. SACK bits are relative to each incoming ACK's own
`next_expected`, not the merged cumulative value. Reject ACKs that acknowledge
unsent sequences or overflow sequence/credit arithmetic. A.7 includes reordered
ACK and lost-credit-update traces.

A direction's first bytes form a bounded opening record: the client sends OPEN
with the SOCKS address type, address, and port; the server sends an OPEN_RESULT
with a SOCKS-compatible status and bound address. These records travel through
ordinary sequenced SEGMENTs, so long hostnames can span several DNS queries
without a separate fragmentation protocol. The receiver consumes the opening
record before interpreting subsequent bytes as application data. Cap the record
at 512 bytes and reject invalid or incomplete records after the open deadline.

Appendix A freezes numeric codes, byte layouts, the handshake, and test vectors.

## 5. ARQ and flow control

Use selective repeat separately for each stream direction:

1. Split the byte stream into immutable, sequence-numbered segments.
2. Retain each segment until acknowledged by STREAM_ACK. Acknowledge only after
   bounded receive storage has accepted it; acknowledge duplicates again
   without delivering them twice.
3. Buffer out-of-order segments, but deliver only contiguous data.
4. Send a STREAM_ACK for each stream whose receive state changed, piggybacked
   on outgoing data or polls where space permits. A response always includes a
   STREAM_ACK for every stream that had SEGMENT or FIN frames in its query, so
   the client never packs frames from more streams into one query than its
   response can acknowledge.
5. Treat a sequence as missing only when the SACK map shows it absent while
   later sequences are present, and the loss rules below say it was sent long
   enough ago. Timeout recovery must work without any gap information.
6. Retransmit only unacknowledged segments. Deduplicate queued retransmissions.

Start with a 32-frame receive window per direction. Let `next_consumed` be the
first sequence not yet consumed by the bounded delivery path. The advertised
exclusive credit limit is `max(next_consumed + 32, next_expected)`. For data,
credit advances only on consumption, not receipt or acknowledgement; this keeps
a slow destination from accumulating unlimited acknowledged data. The sole
exception is acknowledging a credit-free FIN at the window boundary: the limit
advances to `next_expected` so `credit_delta` remains nonnegative. No data may
follow FIN, so this exception cannot admit additional payload. The limit is
monotonic, and the receiver repeats STREAM_ACK periodically while the sender
appears blocked on credit, so a lost STREAM_ACK cannot stall the stream. Initial
credit is fixed by the protocol. The 32-bit SACK map covers the 32-frame data
window plus a FIN at its credit boundary.

Bound both frame counts and byte storage. Check credit before sending new data;
retransmissions of already admitted frames remain allowed. FIN needs no credit
and may be accepted at or below the credit limit, but not beyond it: it carries
no payload and occupies no receive storage beyond its recorded sequence number.
FIN may be acknowledged before preceding bytes are consumed, but takes effect
only after they are delivered (§6). For example, with sequences 0–31 received
but unconsumed, accepting FIN 32 produces `next_expected = 33`, credit limit 33,
and `credit_delta = 0`. Stop reading the local TCP socket when outbound capacity
is full. Do not discard received stream bytes to make room: reject unadmittable
frames without acknowledging them.

DNS is strictly request/response, so most loss is detected from exchanges
rather than timers:

- **Client, upload loss.** A response to exchange N proves the server processed
  query N. A SEGMENT or FIN from query N that the response's STREAM_ACK does not
  cover was rejected, and is resent when credit allows. If responses arrive for
  exchanges at least 3 later than N while N's response is still missing, treat
  query N or its response as lost and queue its unacknowledged frames
  immediately.
- **Server, download loss.** The server records which response carried each
  SEGMENT or FIN. A query with `rx_lag` in 1–254 identifies the highest received
  response as `exchange_id - rx_lag`. If that response is at least 3 exchanges
  after the response that carried a frame, and the frame is still unacknowledged
  after applying the query's STREAM_ACKs, mark it lost and eligible for the next
  response. A value of 255 is ambiguous: never subtract it to infer a received
  response or treat it as new delivery evidence. Still apply the query's
  STREAM_ACKs normally; use other valid evidence or RTO for loss recovery.
- The reordering allowance of 3 exchanges is a starting point to tune against
  real resolvers.

Use one RTO algorithm for all reliable segments and FINs as the fallback when
exchange evidence is absent, such as when every response is being lost:

- Start the timer on actual transport dispatch, not queue insertion.
- Track smoothed RTT and RTT variance; sample only frames never retransmitted.
  Server-side samples include the client's polling delay, which is why
  exchange-based detection is primary on the server.
- Initial RTO 1 second, clamped to 250 milliseconds through 5 seconds.
- Exponential backoff after timeout; rate-limit gap-driven retransmissions so
  one stream cannot monopolize the pipeline.
- The server can transmit only inside a response, so its RTO only makes frames
  eligible for the next response.
- Reset a stalled stream after a bounded no-progress deadline, initially
  120 seconds. Ordinary idle TCP connections are not stalled transfers.

FIN consumes a sequence number and uses the same acknowledgement and
retransmission machinery. Do not acknowledge data that cannot be retained or
silently abandon missing stream data.

## 6. Stream lifecycle

```text
Opening -> Established -> Half-closed -> Closed
    any nonterminal state -> Reset
```

Receiving OPEN starts at most one destination connection attempt. Duplicate
segments cannot start additional connections. Retain/retransmit the opening
result until ACKed, and send SOCKS success only after the destination connects.
Allow 30 seconds for opening, including server-side name resolution and dialing.
Do not read application data until the local SOCKS success reply is written.

On local EOF, enqueue FIN after all preceding bytes. A received FIN takes effect
only after preceding data is delivered, then shuts down the destination's TCP
write half. Keep the opposite direction alive. Close fully after both directions
finish and all local reliable frames are ACKed.

RESET aborts immediately and is idempotent. Repeat it for a bounded interval.
Short-lived tombstones re-ACK late FINs after graceful closure and answer traffic
for aborted streams with RESET. Preventing stream resurrection does not depend
on tombstone retention: each session also keeps a high-water mark and a used-ID
bitmap for its stream-ID reorder window (at least the maximum concurrent stream
count). Mark an ID used before admitting its first stream frame, and never clear
that mark while the ID remains in the window, even on failed admission or
closure. IDs that leave the window can never create streams again. Existing
active streams remain valid even if their IDs fall below the window. After a
tombstone expires or is evicted, traffic for a used or too-old ID receives
RESET(unknown or closed stream), not a new connection attempt. A.5 specifies the
window boundaries and admission order.

If a session expires or the server restarts, fail its SOCKS connections. Reconnect
for new connections, but never replay an established application's bytes into a
new destination connection.

Session loss must be detected promptly rather than inferred from stream stalls:

- The server answers a well-formed tunnel query for an unknown session ID with
  SESSION_ERROR(unknown session), XORed with the configured key like every other
  envelope. This error, like all traffic, is unauthenticated and can be forged
  by a capable attacker. Rate-limit these replies per resolver address.
- On SESSION_ERROR(unknown session), the client fails the session's streams
  immediately and establishes a new session on demand.
- The client also declares the session dead after 60 seconds without any valid
  response, matching server expiry, and handles it the same way.

## 7. DNS transport and polling

### 7.1 Encoding

Use UDP DNS TXT questions. XOR the serialized envelope, then encode it as
unpadded lowercase base32 labels, each at most 63 characters, followed by the
tunnel domain. Decode names case-insensitively because resolvers may change case,
then remove XOR before parsing the envelope.

A tunnel response carries exactly one TXT resource record whose character
strings, concatenated in order, form the XORed binary envelope. Never split an
envelope across several TXT records: resolvers may reorder the records in a set
or remove duplicates, but they preserve string order within one record.

Set answer TTL to zero, but do not rely on caches honoring it: fresh exchange IDs
make every query name unique. The server always responds promptly, even when
there is no download data. It never sends unsolicited DNS responses. Holding a
query briefly on the server until download data is ready (long polling) would
cut latency and idle query rate. It is a candidate follow-up after v1
measurements, not part of v1.

### 7.2 Payload budget and segment sizes

Keep complete responses within 512 bytes initially. Budget the actual encoded
question, DNS header, answer record overhead, the server's own OPT record when
the query carried one, and TXT length octets; never assume the whole 512 bytes
is tunnel payload. XOR preserves length and there are no authentication tags.
Query names must fit the 255-byte wire-name limit. Reject domains leaving
insufficient room for the largest handshake message or a segment with at least
16 payload bytes.

Use fixed directional segment sizes calculated during the handshake from the
domain and fixed framing overhead, and keep segment bytes unchanged across
retransmissions. Pack only whole frames that fit.

- **Upload segment size U:** the largest payload such that a maximum-length
  query name carries the client header, one STREAM_ACK, and one SEGMENT.
- **Download segment size D:** the largest payload such that the response to a
  maximum-length query carries the server header, one STREAM_ACK, and one
  SEGMENT. If, at that size, the response to a minimal poll (a query carrying
  one STREAM_ACK) can hold only one SEGMENT, reduce D to the largest size that
  fits two. Most download data travels in poll responses, so sizing D only for
  the worst case would waste up to half of every poll response.

Worked example for `t.example.com` (15 wire bytes):

| Quantity | Bytes or count |
| --- | --- |
| Envelope bytes in a maximum-length query (236 base32 characters) | 147 |
| U (147 − 10 header − 16 STREAM_ACK − 10 SEGMENT) | 111 |
| Envelope bytes in the response to that query (512 − 12 header − 259 question − 12 answer − 11 OPT − 1 TXT length) | 217 |
| D (217 − 9 header − 16 STREAM_ACK − 10 SEGMENT) | 182 |
| Frame bytes in the response to a minimal poll | 404 |
| SEGMENTs of size D per poll response | 2 |

No MTU probing, EDNS size negotiation, IP fragmentation dependence, or
DNS-over-TCP fallback in v1.

### 7.3 Duplicate queries and the response cache

Recursive resolvers routinely deliver the same query more than once, through
retries after a timeout or by fanning out across several backends. Only one
copy's response may reach the client, so each exchange must produce exactly one
envelope:

- Each session tracks a sliding window of the 1024 most recent exchange IDs
  seen, and caches the response envelope for each recent exchange. Cache
  retention is bounded by count (initially 256 envelopes per session) and age
  (initially 5 seconds), and counts against the aggregate buffer limit (§9).
- A duplicate exchange ID whose envelope is cached receives the identical
  envelope again, without reprocessing the query's frames. Frames dequeued into
  the first response are therefore never stranded in a response the client
  cannot receive.
- A duplicate whose envelope has been evicted, or an exchange ID below the
  window, is dropped without a response.
- An unseen exchange ID inside the window is processed normally; queries may
  arrive out of order.
- Cache envelopes, not DNS messages. Each copy of a query may carry a different
  DNS transaction ID, question-name case, or EDNS option, so the DNS wrapper is
  rebuilt for every reply.
- Validate envelope structure before consulting the cache. This is duplicate
  suppression, not security replay protection: without authentication a forged
  query can retrieve cached data or inject new frames if the attacker learns
  the XOR key and session identifiers.

### 7.4 Non-tunnel queries

The server is authoritative for the tunnel domain and must behave like a plain
authoritative server for everything that is not a valid tunnel query. Many
resolvers minimise query names (RFC 9156): before asking for the full name,
they send A or NS queries for partial names under the tunnel domain. A resolver
following RFC 8020 treats an NXDOMAIN for such a partial name as proof that
nothing exists below it, so a single NXDOMAIN can break all tunnel traffic
through that resolver.

- Names outside the tunnel domain: REFUSED.
- SOA at the apex: a synthesized SOA record with short timers.
- Any other in-zone name or type that is not a decodable tunnel TXT query,
  including partial names, apex NS, and other query types: NOERROR with no
  answer (NODATA), authoritative, with the synthesized SOA in the authority
  section. Never answer NXDOMAIN inside the zone.
- A decodable tunnel query for an unknown session: SESSION_ERROR (§6).
- Echo the question section byte-for-byte as received, because some resolvers
  randomise letter case (0x20) and reject responses whose case differs.
- If the query carried an EDNS OPT record, include an OPT record without
  options in the response. Never set TC: responses are budgeted to fit.

Partial-name queries also multiply authoritative query count for every tunnel
exchange. Measure this against minimising resolvers before tuning the pipeline.

### 7.5 Pipeline and polling

The client keeps a bounded pipeline of outstanding queries. Throughput is
roughly pipeline depth × payload per response ÷ resolver round trip. With four
outstanding queries, two 182-byte segments per response, and a 200 ms round
trip, download tops out near 7 KB/s, so the depth must adapt:

- Start at 4 outstanding queries, with a maximum of 32.
- Increase the depth by one for each response that has MORE_PENDING set, or
  while upload data is waiting for a query slot.
- Halve it, to no fewer than 2, on a query timeout.
- Decay it back toward 4 while the session is idle.
- Spread queries across the round trip rather than sending them in bursts.

At full depth, a single stream is limited by its 32-frame receive window, about
32 segments per round trip; measure whether that binds before changing the
window.

Upload queries also collect download frames. When streams exist but uploads are
quiet, send polls (empty envelopes, or envelopes carrying only STREAM_ACKs) to
retrieve downloads and control traffic. MORE_PENDING keeps polling active.
Repeated empty responses back off in stages:

| Time since last activity | Poll interval |
| --- | --- |
| 0–10 seconds | about 1 second |
| 10–60 seconds | 5 seconds |
| Over 60 seconds | 15 seconds |

Any local upload data, received download data, or MORE_PENDING returns the
client to active polling. With no streams, send a keepalive every 15 seconds,
well inside the 60-second server session expiry. The cost of this backoff is
latency for data the server initiates on a quiet connection: up to 15 seconds
in the slowest stage. Long polling (§7.1) would remove it.

Prioritize control frames and due retransmissions, then round-robin new data
across streams. Keep STREAM_ACK batches bounded so they cannot starve data
indefinitely.

### 7.6 Response validation

Validate resolver source address, DNS transaction ID, question name, TXT answer,
session ID, and exchange ID against outstanding queries. Discard unsolicited,
late-completed, malformed, truncated, and mismatched responses. DNS failure or
query timeout does not imply stream delivery failure: ARQ owns stream recovery.

## 8. XOR and unauthenticated session establishment

V1 has one operating mode: repeating-key XOR, with no client/server
authentication, envelope MAC, or plaintext fallback. Both sides require the same
nonempty XOR key file. There is no mode negotiation or token option.

XOR every serialized envelope with the repeating key bytes before DNS encoding,
restarting at key offset zero for every envelope in either direction. Reverse
XOR before parsing. DNS headers, question metadata, TXT length octets, and other
DNS framing are not XORed. A key mismatch normally produces undecodable traffic
or failed validation; without authentication it cannot be detected reliably.
Never retry using plaintext. XOR is not encryption or access control: known
headers reveal key bytes, and a capable attacker can read, modify, inject, or
terminate traffic. Use application TLS for sensitive data.

Keep a stateless cookie exchange to defer session allocation until the client
returns a server-issued challenge:

1. HELLO supplies a random 128-bit client nonce.
2. CHALLENGE supplies a server nonce, fixed transport parameters, and a
   short-lived cookie. Bind the cookie to both nonces, expiry, version, domain,
   and transport parameters using a random server-only secret. It is not bound
   to UDP source address because recursive resolver paths may change. No
   destination connections or durable session state are created yet.
3. COOKIE_ECHO returns both nonces and the cookie. Anyone who obtains a valid
   challenge can complete this step; it proves neither identity nor permission.
4. ACCEPT assigns a random session ID. Cache the completed handshake so retries
   return that same session, rebuilding the response for each retry's exchange
   ID (A.4).

HMAC-SHA256 is used only to prevent fabrication of server cookies, not to
authenticate peers or protect envelopes. The server-only cookie secret is
independent of the shared XOR key. Expire cookies, bound handshake rate and cache
size, and generate nonces and server secrets using OS randomness.

## 9. Resource limits and diagnostics

Initial internal limits: 64 streams per session, 64 server sessions, 32 MiB
aggregate server protocol buffering (including response caches), bounded
handshake/tombstone tables, and a session expiry of 60 seconds without valid
client traffic. Enforce limits before
allocation and return bounded errors. Limits may change after tests, without
becoming CLI options by default.

Expose concise logs for session establishment/loss, connection failures,
unauthenticated XOR operation, and resource exhaustion. Debug logs may include
counters, RTT/RTO, queue occupancy, retransmissions, and query failures, but not
payloads or secrets. Log refused destinations at debug level. This deployment
remains an intentional open proxy; resource limits and XOR do not provide access
control. The destination filter (§2) limits where that proxy can reach.

## 10. Implementation and verification order

1. Implement the bounded codecs from Appendix A, reproduce its test vectors,
   and add malformed-input tests.
2. Implement pure ARQ and simulated-clock/network tests for loss, duplication,
   reordering, lost STREAM_ACKs, exchange-based loss detection, credit stalls,
   and counter exhaustion.
3. Add DNS framing, segment-size and payload-budget tests, non-tunnel query
   answers, the response cache, and a local client/server round trip.
4. Add the cookie handshake, duplicate/replay handling, and required XOR.
5. Add SOCKS CONNECT, name resolution, the destination filter, opening errors,
   and TCP half-close.
6. Exercise concurrent streams, adaptive pipeline depth, idle polling backoff,
   session loss detection, and end-to-end fault injection.

Acceptance tests must demonstrate: exact byte delivery; no duplicate destination
connections; one lossy stream not blocking unrelated streams; bounded memory
under slow readers; correct FIN handling; explicit failure after session loss;
XOR on every envelope, including handshake/error responses; rejection of missing
or empty keys, and no plaintext fallback; no response stranded by duplicate
queries; refusal of internal destinations, including through a hostile DNS
answer; and
operation through real recursive resolvers. Include Unbound and BIND with query
name minimisation and 0x20 case randomisation enabled, plus major public
resolvers, whose retry and duplicate-query behaviour differs. Fuzz the
binary/DNS parsers and test long tunnel domains and 255-byte destination names.
Measure useful throughput, authoritative queries per exchange, and idle query
rate before tuning constants.

Required regression cases for the state invariants:

- Receive segments 0–31 without consuming them, then FIN 32. The ACK must encode
  `next_expected = 33`, `sack = 0`, and `credit_delta = 0`; retain all bytes and
  defer TCP write shutdown until delivery completes. Also test FIN arriving
  before gaps are filled, duplicate FINs, and rejection of data at or after FIN.
- At exchange 1000 with `rx_lag = 255`, do not infer receipt of response 745,
  whether the actual highest received response is 700 or none. Apply explicit
  STREAM_ACKs and retain timeout recovery. Test the exact/ambiguous boundary at
  lag 254/255 and recovery when a later query supplies an exact lag again.
- Close or reject a stream, expire or evict its tombstone, and retransmit its
  opening bytes under a fresh exchange ID. Never allocate another stream or
  destination connection. Test both an ID still in the used-ID bitmap and one
  below the window; also verify that unseen in-window IDs can open and active
  streams continue working after their IDs leave the window.
- Drop ACCEPT and retry COOKIE_ECHO with a fresh exchange ID; return the same
  session in a newly framed response. Reject expired or tampered cookies even
  when their nonces match a completed handshake. Do not evict live handshake
  cache entries to admit new ones.
- Deliver ACKs out of order and drop a credit update. Cumulative acknowledgement,
  retained SACK evidence, and the credit limit must not regress; a periodic ACK
  repeat must repair the lost credit update. Include ACKs of unsent sequences
  and sequence/credit overflow as rejected inputs. A.7 supplies executable
  reference traces for these cases and the three invariants above.

## Appendix A. Wire specification

This appendix freezes the byte-level details for protocol version 1. Where it
is more specific than the main text, it governs. Everything here is
interoperability-relevant unless marked local.

### A.1 Conventions

- All integers are unsigned and big-endian.
- Protocol version is 1. `ver_flags` carries the version in bits 7–5 and flags in
  bits 4–0, so a version 1 envelope with no flags has `ver_flags = 0x20`.
- The server-cookie HMAC label is the ASCII byte string
  `b"cloudyday v1 cookie"`, with no terminator.
- `domain_wire` is the tunnel domain in DNS wire format, lowercased, ending
  with the root label. For `t.example.com`, that is
  `01 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00`.

### A.2 DNS messages

**Client query**

- Header: random 16-bit ID from the OS RNG for every query; flags `0x0100`
  (RD set, all else clear); QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 1.
- Question: QNAME is the base32 XORed-envelope labels followed by the tunnel domain;
  QTYPE TXT (16); QCLASS IN (1).
- Additional: an OPT record with UDP payload size 1232, extended RCODE 0,
  version 0, DO clear, and no options. This gives the resolver room for
  records it adds; the server still keeps its own responses within 512 bytes.
- The client uses one UDP socket, connected to the resolver address, so the
  kernel discards datagrams from any other source.

**Base32 and labels**

- Alphabet: RFC 4648 standard, lowercase `abcdefghijklmnopqrstuvwxyz234567`;
  no padding; bits packed most significant first.
- Labels are filled left to right: every label except the last holds exactly
  63 characters, and the last holds 1–63.
- Decoders accept either letter case, but reject a name that is not in this
  canonical shape: labels of the wrong length, a character count that is
  impossible for unpadded base32 (count mod 8 is 1, 3, or 6), or nonzero
  unused bits in the final character. Every envelope therefore has exactly one
  valid query name, apart from letter case.

**Server tunnel response**

- Header: ID copied from the query; QR and AA set, RD copied, RA clear, TC
  clear, RCODE NOERROR; QDCOUNT 1, ANCOUNT 1, NSCOUNT 0, and ARCOUNT 1 if the
  query had an OPT record, otherwise 0.
- Question: the query's question section, copied byte for byte.
- Answer: NAME `c0 0c` (pointer to the question name), TYPE TXT, CLASS IN,
  TTL 0, then RDATA holding the XORed envelope as consecutive character strings of
  255 bytes, with the last string holding 1–255 bytes.
- Additional, if the query had an OPT record: OPT with UDP payload size 1232,
  zero TTL fields, and no options.
- Responses never exceed 512 bytes. Treat a response that would exceed that
  as an internal error, never as a reason to set TC.

**Non-tunnel responses (§7.4)**

- The synthesized SOA record has owner equal to the tunnel domain, MNAME the
  tunnel domain, RNAME `hostmaster.` followed by the tunnel domain, SERIAL 1,
  REFRESH 3600, RETRY 600, EXPIRE 86400, MINIMUM 0, and TTL 0.
- A query counts as a decodable tunnel query when all of the following hold:
  QTYPE is TXT, QCLASS is IN, the name lies under the tunnel domain with
  canonical base32 labels, the decoded and de-XORed envelope is at least as long
  as the client header, and the version is 1.
- A query that meets every condition except the version gets
  SESSION_ERROR(unsupported version). Anything else that fails these checks
  gets NODATA.

**Client response checks.** The response must:

- match an outstanding query by DNS ID;
- have RCODE NOERROR and TC clear;
- have a question name equal to the one sent, ignoring letter case;
- contain exactly one TXT record owned by that name in the answer section.

The client ignores the authority and additional sections. SERVFAIL, REFUSED,
or any other RCODE frees the pipeline slot at once and counts as a query
timeout for pipeline depth (§7.5).

**Implementation note (local).** Parse incoming messages with the DNS library.
Build tunnel responses with a small fixed-layout writer that copies the raw
question bytes, because the response layout is fixed and must echo the
question's letter case exactly.

### A.3 Envelope

| Field | Client → server | Server → client |
| --- | --- | --- |
| `ver_flags` | u8 | u8 |
| `session_id` | u32 | u32 |
| `exchange_id` | u32 | u32 |
| `rx_lag` | u8 | absent |
| Header size | 10 bytes | 9 bytes |

**Flags**

| Bit | Mask | Name | Notes |
| --- | --- | --- | --- |
| 1 | 0x02 | MORE_PENDING | Valid only from the server |
| 0, 2–4 | 0x1d | reserved | Must be zero; reject envelopes that set them |

**Exchange IDs**

- During a handshake, envelopes use `session_id` 0. Exchange IDs count from 1
  for each handshake, and `rx_lag` is 255.
- After ACCEPT, the session's exchange IDs count from 1 again.
- The client must establish a new session before its exchange ID would pass
  `0xffffffff`.
- `rx_lag` is `min(255, exchange_id − highest exchange ID with a received
  response)`, or 255 if the session has received no response yet. Only validated
  responses contribute to that highest ID.
- Values 1–254 identify the highest received response exactly. The value 255
  means unknown or at least 255 behind; it MUST NOT establish response receipt
  or advance exchange-based delivery evidence. STREAM_ACK processing and RTO
  recovery remain enabled. Zero is invalid; an exact lag must be less than the
  query's exchange ID, since session response IDs start at 1.

**XOR.** Byte `i` of the complete envelope, counted from `ver_flags`, is XORed
with `key[i mod key_len]`. This is required for every envelope in both directions,
including handshake and SESSION_ERROR. There is no authentication tag. Senders
serialize, XOR, then encode in DNS; receivers decode DNS, remove XOR, then parse
and validate. The key offset restarts at zero for each envelope, not each frame,
label, or TXT character string.

**Frames.** Each frame is `kind: u8 | length: u8 | body`. Frames repeat until
the end of the envelope. A frame whose length runs past that point, or an unknown
kind, invalidates the whole envelope.

| Code | Frame | Direction | Body |
| --- | --- | --- | --- |
| 0x01 | HELLO | C→S | A.4 |
| 0x02 | CHALLENGE | S→C | A.4 |
| 0x03 | COOKIE_ECHO | C→S | A.4 |
| 0x04 | ACCEPT | S→C | A.4 |
| 0x10 | SEGMENT | both | `stream: u32, seq: u32, payload` (1 to U or D bytes) |
| 0x11 | FIN | both | `stream: u32, seq: u32` |
| 0x12 | STREAM_ACK | both | `stream: u32, next_expected: u32, sack: u32, credit_delta: u16` |
| 0x13 | RESET | both | `stream: u32, reason: u8` |
| 0x20 | SESSION_ERROR | S→C | `reason: u8` |

**Where frames may appear**

- A handshake envelope (`session_id` 0) carries exactly one handshake frame,
  or a SESSION_ERROR as specified below.
- SESSION_ERROR travels alone in an envelope that echoes the query's
  `session_id` and `exchange_id`; XOR still applies.
- All other frames appear only in post-handshake envelopes.
- A STREAM_ACK describes the direction of the stream that its sender
  receives.

**RESET reasons**

| Code | Meaning |
| --- | --- |
| 0x00 | Unspecified |
| 0x01 | Local abort: the application or destination connection failed or closed abnormally |
| 0x02 | Stall deadline exceeded (§5) |
| 0x03 | Protocol violation, such as an invalid opening record |
| 0x04 | Resource limit |
| 0x05 | Open deadline exceeded |
| 0x06 | Unknown or closed stream (tombstone or used-ID/window rejection) |
| 0x07 | Sequence space exhausted |

**SESSION_ERROR reasons**

| Code | Meaning | Client action |
| --- | --- | --- |
| 0x01 | Unknown session | Fail the session's streams; establish a new session on demand |
| 0x02 | Unsupported version | Fail with a version error; do not retry |
| 0x03 | Server busy | Fail pending opens; wait at least 5 s before another handshake |
| 0x04–0x05 | Reserved | Reject as an unknown error code |
| 0x06 | Handshake expired | Restart the handshake with a fresh HELLO |

### A.4 Handshake

There is no mode field, token proof, or session MAC key. Every handshake envelope
uses session ID zero, including ACCEPT; its body supplies the new session ID.

| Frame | Body | Size |
| --- | --- | --- |
| HELLO | `client_nonce: [16]` | 16 |
| CHALLENGE | `server_nonce: [16] \| U: u16 \| D: u16 \| cookie: [20]` | 40 |
| COOKIE_ECHO | `client_nonce: [16] \| server_nonce: [16] \| cookie: [20]` | 52 |
| ACCEPT | `session_id: u32` | 4 |

**Server side**

- **HELLO.** If the session table is full, reply SESSION_ERROR(busy). Otherwise,
  reply CHALLENGE with a fresh server nonce, the segment sizes computed under
  §7.2, and a cookie. The server keeps no state for the HELLO.
- **Cookie (local construction).** The cookie is opaque to the client. The
  recommended form is `expiry: u32 (Unix seconds) ||
  HMAC-SHA256(server_secret, b"cloudyday v1 cookie" || version: u8 ||
  domain_wire || client_nonce || server_nonce || expiry: u32 || U: u16 || D: u16)[0..16]`.
  `server_secret` is 32 random bytes generated at startup, independent of the
  XOR key. Compare the cookie MAC in constant time. At `now >= expiry`, the
  cookie is expired.
- **COOKIE_ECHO.** Verify the cookie and expiry before consulting the handshake
  cache; failure returns SESSION_ERROR(handshake expired). Look up the cache by
  the full `(client_nonce, server_nonce, cookie)` tuple under the current domain,
  version, and transport parameters. On a cache hit, reuse the assigned session
  ID, but rebuild ACCEPT with the current query's exchange ID and apply XOR.
  Never reuse an envelope carrying an earlier exchange ID. On a cache miss:
  - recheck capacity; if full, reply SESSION_ERROR(busy);
  - assign a random nonzero session ID not in use;
  - store the assignment and send ACCEPT.
- Retain completed-handshake entries until their cookies expire. If cache
  capacity is exhausted, refuse new handshakes with SESSION_ERROR(busy) rather
  than evict a live entry and risk allocating twice for a valid cookie retry.

**Client side**

- Send HELLO and accept the first valid CHALLENGE matching an outstanding HELLO
  query, ignoring later challenges for the same handshake.
- Require U and D to equal the client's own §7.2 computation. A mismatch fails
  establishment with a configuration error.
- Retransmit COOKIE_ECHO with an identical body and a fresh exchange ID.
- Accept ACCEPT only if it matches an outstanding COOKIE_ECHO query and contains
  a nonzero session ID. There is no cryptographic verification of the server.

**Retries (local).**

- Handshake messages time out after 2 s, doubling to at most 8 s per attempt.
- A handshake has 30 s overall. Only one handshake runs at a time.
- After a failure, wait at least 5 s before another attempt.
- If no valid reply arrives at all, report a probable domain, resolver, or XOR
  key mismatch. Wrong-key traffic is not guaranteed to be distinguishable from
  other malformed traffic; never fall back to plaintext.

### A.5 Streams and opening records

**Stream state**

- Stream IDs start at 1 and increase.
- Sequence numbers start at 0 in each direction.
- Initial credit is the full window: sequences 0–31 may be sent before any
  STREAM_ACK arrives.

**Credit and FIN**

Let `C` be the first sequence not yet consumed by the bounded delivery path and
`N` be `next_expected`. Encode each STREAM_ACK using:

```text
credit_limit = max(C + 32, N)
credit_delta = credit_limit - N
```

Use checked arithmetic; reset the stream before sequence or credit calculations
would overflow `u32`. FIN consumes a sequence number but no data credit. Accept
it only at or below the current credit limit, retaining its sequence number;
acknowledge it cumulatively or through SACK like a SEGMENT. A FIN beyond the
limit is not admitted or acknowledged. If FIN fills the final gap at the credit
boundary, `N` may become `C + 33`, yielding `credit_delta = 0`. This terminal
exception never grants permission to send data at or after FIN.

A direction has only one FIN sequence. Duplicate FINs at that sequence are
idempotent. A different FIN sequence, a SEGMENT at or after an accepted FIN, or
a FIN at or below already accepted data is a protocol violation: reset the
stream. Retaining or acknowledging FIN does not consume earlier bytes or shut
down TCP; apply FIN only after all preceding bytes have been delivered.

**Server stream-ID admission**

Maintain a high-water mark `H`, initially 0, and a used-ID bitmap of width `W`
(the local reorder allowance, initially 64). The bitmap represents IDs
`max(1, H - W + 1)` through `H`; compute bounds without unsigned underflow.

For a valid SEGMENT or FIN, after envelope validation:

1. Reject stream ID zero as a protocol violation. If the ID belongs to an active
   stream, process it there regardless of its position relative to the window.
   If a tombstone exists, use its FIN-ACK or RESET response.
2. Otherwise, if the ID is below the window or its used bit is set, send
   RESET(unknown or closed stream). Never create stream state or dial again.
3. For an ID above `H`, advance `H` and shift the bitmap to the new window;
   discard only bits for IDs now permanently below the window and initialize
   newly represented bits to zero. For an unseen ID already inside the window,
   leave `H` unchanged.
4. Set the ID's used bit before allocating stream state or starting asynchronous
   work. Then attempt admission; on resource failure, send RESET(resource limit)
   and retain the used bit. Closure, reset, and tombstone expiry or eviction
   never clear used bits. The high-water mark and bitmap live for the session.

**OPEN** (client → server; the first bytes of the client's direction):

```text
atyp: u8 | address | port: u16
  atyp 0x01: address = IPv4 [4]
  atyp 0x04: address = IPv6 [16]
  atyp 0x03: address = len: u8 (1..=255) | name [len]
```

The longest OPEN is 259 bytes. Names may contain only ASCII letters, digits,
`-`, `_`, and `.`; applications send internationalized names in punycode. If
the record is malformed or uses an unknown `atyp`, the server sends
RESET(protocol violation).

**OPEN_RESULT** (server → client; the first bytes of the server's direction):
`status: u8 | atyp: u8 | address | port: u16`, with the same address encoding
except that `atyp` 0x03 is not used.

- On success, the address is the local address of the destination socket.
- On failure, the address is `0x01 0.0.0.0:0`, and the server sends FIN
  immediately after the record. The client relays the status as its SOCKS
  reply and finishes the stream normally.

| Status | Server condition |
| --- | --- |
| 0x00 | Connected |
| 0x01 | Any other failure |
| 0x02 | Refused by the destination filter (§2), including when every resolved address is refused |
| 0x03 | Network unreachable |
| 0x04 | Host unreachable, name resolution failure, or no addresses |
| 0x05 | Connection refused |
| 0x06 | Open deadline (30 s) exceeded |

**Dialing.** For domain destinations, the server resolves with the system
resolver and filters every address. It then tries the remaining addresses in
the order returned, one at a time, each within the remaining open deadline.
The first success wins. Happy Eyeballs is not used in v1.

**Client SOCKS side**

- Offer only the no-authentication method, and accept only CONNECT. Reply
  `0xff` to other method sets, `0x07` to other commands, and `0x08` to unknown
  address types.
- If no session exists, a CONNECT starts or joins the handshake. The 30 s open
  deadline covers the handshake too. On expiry, reply `0x01`, or the status
  matching any SESSION_ERROR received.

### A.6 Constants

Protocol constants must match on both sides. Changing one requires a new
version.

| Constant | Value |
| --- | --- |
| Version | 1 |
| Obfuscation; authentication | Required repeating-key XOR; no peer authentication or envelope tag |
| Receive window and initial credit | 32 frames |
| SACK map width | 32 bits |
| Maximum DNS response | 512 bytes |
| Base32 alphabet and label layout | A.2 |
| Segment sizes U and D | Derived by §7.2 and confirmed in CHALLENGE |
| Nonce length; cookie length | 16 bytes; 20 bytes |

Local constants are starting points that each side may tune independently:

| Constant | Initial value |
| --- | --- |
| Query timeout and RTO | Initial 1 s, clamped to 250 ms–5 s; the client samples RTT from every exchange, which is unambiguous because exchange IDs are never reused |
| Pipeline depth | 4 at start, 2 minimum, 32 maximum |
| Loss reorder allowance | 3 exchanges |
| Gap-driven retransmit | At most once per sequence per RTO |
| Credit repeat | STREAM_ACK every 1 s after the credit limit advances, until the peer sends a sequence at or beyond the previous limit, at most 5 times; afterwards at the keepalive interval |
| RESET repeat | Every 1 s for 5 s |
| Tombstone lifetime | 60 s, at most 256 per session; eviction does not erase used-ID history |
| Stream ID reorder allowance | 64; used-ID bitmap retained for the session and shifted only as the high-water mark advances |
| Stall deadline; open deadline | 120 s; 30 s |
| Session expiry (server); dead timer (client) | 60 s; 60 s |
| Keepalive; idle poll tiers | 15 s; 1 s / 5 s / 15 s after 0 / 10 / 60 s idle |
| Exchange window; response cache | 1024 IDs; 256 envelopes or 5 s |
| Cookie lifetime; handshake cache | 30 s; retain until cookie expiry, at most 256 entries (refuse new entries when full) |
| Handshake rate | 10 per second, burst 20, for the whole server |
| SESSION_ERROR rate | 10 per second per resolver address |
| Limits | 64 streams per session, 64 sessions, 32 MiB of buffering |

### A.7 Test vectors

`python3 tools/gen_vectors.py` regenerates this section using only the Python
standard library. `python3 tools/gen_vectors.py --check` runs the vector
assertions and verifies that this section is current. These are codec examples
and small state-transition oracles, not substitutes for implementation tests.

Unless noted otherwise, use session `0x01020304`, domain `t.example.com`, and
XOR key `5a a5 3c`. `plain` means serialized bytes before XOR, never plaintext
on the wire. All query names and DNS packets below include required XOR.

**V1: XOR client poll.**

Exchange 5, `rx_lag = 1`, no frames; DNS ID `0x1234`.

```text
poll plain: 20 01 02 03 04 00 00 00 05 01
poll XOR:   7a a4 3e 59 a1 3c 5a a5 39 5b
poll qname: pksd4wnbhrnkkok3.t.example.com
DNS query (59 bytes):
12 34 01 00 00 01 00 00 00 00 00 01 10 70 6b 73
64 34 77 6e 62 68 72 6e 6b 6b 6f 6b 33 01 74 07
65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 10 00 01
00 00 29 04 d0 00 00 00 00 00 00
```

**V2: STREAM_ACK and SEGMENT.**

ACK stream 1: next expected 3, SACK bit 1 (sequence 5), credit limit 33.
SEGMENT stream 1: sequence 0, payload `hello`. The query spans two labels.

```text
mixed plain: 20 01 02 03 04 00 00 00 06 01 12 0e 00 00 00 01 00 00 00 03 00 00 00 02 00 1e 10 0d 00 00 00 01 00 00 00 00 68 65 6c 6c 6f
mixed XOR:   7a a4 3e 59 a1 3c 5a a5 3a 5b b7 32 5a a5 3c 5b a5 3c 5a a6 3c 5a a5 3e 5a bb 2c 57 a5 3c 5a a4 3c 5a a5 3c 32 c0 50 36 ca
mixed qname: pksd4wnbhrnkkos3w4zfvjj4lostywvghrnkkps2xmwfpjj4lksdywvfhqzmaub.wzi.t.example.com
```

**V3: cookie handshake, no peer authentication.**

All envelope session IDs are zero; ACCEPT assigns `0x01020304`. Use the
recommended cookie construction with server secret bytes `00`–`1f`, client
nonce `00`–`0f`, server nonce `10`–`1f`, expiry 1700000030, and U=111, D=182.
The cookie HMAC is server-only; no envelope carries a MAC or token proof.

```text
cookie: 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57
HELLO plain: 20 00 00 00 00 00 00 00 01 ff 01 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
HELLO XOR:   7a a5 3c 5a a5 3c 5a a5 3d a5 a4 2c 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55
CHALLENGE plain: 20 00 00 00 00 00 00 00 01 02 28 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 6f 00 b6 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57
CHALLENGE XOR:   7a a5 3c 5a a5 3c 5a a5 3d 58 8d 2c 4b b7 2f 4e b0 2a 4d bd 25 40 be 20 47 bb 23 5a ca 3c ec c0 6f ab bb ac 2d 17 4b fa 0e eb 9a 46 dd 4f f0 f8 63 94 6b
COOKIE_ECHO plain: 20 00 00 00 00 00 00 00 02 ff 03 34 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57
COOKIE_ECHO XOR:   7a a5 3c 5a a5 3c 5a a5 3e a5 a6 08 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55 b5 2d 48 b6 28 4f b3 2b 42 bc 26 41 b9 21 44 ba 59 09 54 22 ca d2 8e 2d 05 97 8d 65 df bb b0 69 9e 9c 0d 0d
ACCEPT plain: 20 00 00 00 00 00 00 00 02 04 04 01 02 03 04
ACCEPT XOR:   7a a5 3c 5a a5 3c 5a a5 3e 5e a1 3d 58 a6 38
```

**V4: DNS response to V1.**

Empty server envelope for exchange 5. XOR restarts at offset zero; TXT
length octets and DNS framing are not XORed.

```text
response plain: 20 01 02 03 04 00 00 00 05
response XOR:   7a a4 3e 59 a1 3c 5a a5 39
DNS response (81 bytes):
12 34 85 00 00 01 00 01 00 00 00 01 10 70 6b 73
64 34 77 6e 62 68 72 6e 6b 6b 6f 6b 33 01 74 07
65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 10 00 01
c0 0c 00 10 00 01 00 00 00 00 00 0a 09 7a a4 3e
59 a1 3c 5a a5 39 00 00 29 04 d0 00 00 00 00 00
00
```

**V5: full-window FIN and out-of-order FIN.**

For stream 1, retain all 32 data segments without consuming them. A FIN at
sequence 32 is accepted without data credit. Receipt/ACK does not shut down
TCP; only consumption of all preceding bytes does. ACK tuples below are
`(next_expected, sack, credit_delta)`.

```text
data 0..31 received, none consumed: (32, 0x00000000, 0)
SEGMENT 32 / FIN 33: unadmitted
FIN 32 received: (33, 0x00000000, 0); retained data=32; shutdown=false
duplicate FIN 32: unchanged; data >=32 or conflicting FIN: protocol violation
consume data 0..31: shutdown=true
FIN 32 before any data: (0, 0x80000000, 32)
then data 31..0: (33, 0x00000000, 0); shutdown=false
FIN query plain: 20 01 02 03 04 00 00 00 07 01 11 08 00 00 00 01 00 00 00 20
FIN query XOR:   7a a4 3e 59 a1 3c 5a a5 3b 5b b4 34 5a a5 3c 5b a5 3c 5a 85
terminal ACK plain: 20 01 02 03 04 00 00 00 07 12 0e 00 00 00 01 00 00 00 21 00 00 00 00 00 00
terminal ACK XOR:   7a a4 3e 59 a1 3c 5a a5 3b 48 ab 3c 5a a5 3d 5a a5 3c 7b a5 3c 5a a5 3c 5a
```

**V6: saturated lag does not establish delivery.**

At exchange 1000, both highest received response 700 and no response at all
encode lag 255. Neither proves response 745 arrived. Explicit STREAM_ACKs
still apply, and timeout recovery remains enabled.

```text
exchange=1000 lag=254 -> exact highest=746
exchange=1000 lag=255 -> highest=unknown; no new exchange-loss evidence
same query ACK (3, 0x00000002, 30) -> cumulative=3, SACKed=[5], credit=33
exchange=1001 lag=1 -> exact highest=1000
lag=0 or exact lag >= exchange: invalid
saturated query plain: 20 01 02 03 04 00 00 03 e8 ff 12 0e 00 00 00 01 00 00 00 03 00 00 00 02 00 1e
saturated query XOR:   7a a4 3e 59 a1 3c 5a a6 d4 a5 b7 32 5a a5 3c 5b a5 3c 5a a6 3c 5a a5 3e 5a bb
saturated query qname: pksd4wnbhrnknvffw4zfvjj4lostywvghrnkkps2xm.t.example.com
```

**V7: tombstone expiry/eviction never reopens a stream.**

Use a 64-ID window. Expiry and eviction remove only the response tombstone.
Retransmit stream 1's OPEN for `203.0.113.7:443` under fresh exchange 11;
the server must return RESET, not allocate or dial again.

```text
admit 1 -> new; close 1 -> tombstone
retry 1 with tombstone -> tombstone response
remove tombstone; retry 1 -> RESET(0x06), used bit retained
admit 65 -> window [2,65]; retry 1 -> RESET(0x06), too old
admit unseen 2 -> new
reject 3 for resource limit; retry 3 -> RESET(0x06), used bit retained
admit 129 -> window [66,129]; traffic for active 2 -> existing stream
late OPEN plain: 20 01 02 03 04 00 00 00 0b 01 10 0f 00 00 00 01 00 00 00 00 01 cb 00 71 07 01 bb
late OPEN XOR:   7a a4 3e 59 a1 3c 5a a5 37 5b b5 33 5a a5 3c 5b a5 3c 5a a5 3d 91 a5 4d 5d a4 87
RESET plain: 20 01 02 03 04 00 00 00 0b 13 05 00 00 00 01 06
RESET XOR:   7a a4 3e 59 a1 3c 5a a5 37 49 a0 3c 5a a5 3d 5c
```

**V8: lost ACCEPT, cookie validation, and retry identity.**

Drop V3's ACCEPT. Retry COOKIE_ECHO at exchange 3 with the identical body.
Return the same assigned session but rebuild the envelope's exchange ID.
A literal replay of exchange 2's ACCEPT must fail exchange-3 matching.

```text
first ACCEPT dropped; retry -> allocations=1, assigned session=0x01020304
tampered cookie with cached nonces -> SESSION_ERROR(0x06)
now=1700000030 (exact expiry) -> SESSION_ERROR(0x06), allocations still 1
full handshake cache -> SESSION_ERROR(0x03), no live-entry eviction
retry COOKIE_ECHO plain: 20 00 00 00 00 00 00 00 03 ff 03 34 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57
retry COOKIE_ECHO XOR:   7a a5 3c 5a a5 3c 5a a5 3f a5 a6 08 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55 b5 2d 48 b6 28 4f b3 2b 42 bc 26 41 b9 21 44 ba 59 09 54 22 ca d2 8e 2d 05 97 8d 65 df bb b0 69 9e 9c 0d 0d
retry ACCEPT plain: 20 00 00 00 00 00 00 00 03 04 04 01 02 03 04
retry ACCEPT XOR:   7a a5 3c 5a a5 3c 5a a5 3f 5e a1 3d 58 a6 38
expired plain: 20 00 00 00 00 00 00 00 04 20 01 06
expired XOR:   7a a5 3c 5a a5 3c 5a a5 38 7a a4 3a
```

**V9: reordered ACKs and lost credit updates.**

ACK tuples are `(next_expected, sack, credit_delta)`; merged state is
`(cumulative, absolute SACKed sequences, credit limit)`. Sequences 0–11
have been sent for the reorder trace. Interpret each SACK against its own
ACK base and retain positive evidence from older ACKs.

```text
ACK (3, 0x00000002, 29) -> (3, [5], 32)
ACK (6, 0x00000002, 30) -> (6, [8], 36)
stale ACK (3, 0x00000002, 29) -> (6, [8], 36)
older ACK (4, 0x00000009, 28) -> (6, [8], 36)
ACK of unsent sequence or credit arithmetic overflow -> reject
credit trace: send/receive 0..31, ACK (32,0,0) -> blocked at credit=32
consume 0..7; drop ACK (32,0,8) -> sender still blocked
repeat ACK (32,0,8) -> credit=40; new sequences 32..39 allowed, 40 blocked
late ACK (32,0,0) -> credit remains 40
credit repeat plain: 20 01 02 03 04 00 00 00 0c 12 0e 00 00 00 01 00 00 00 20 00 00 00 00 00 08
credit repeat XOR:   7a a4 3e 59 a1 3c 5a a5 30 48 ab 3c 5a a5 3d 5a a5 3c 7a a5 3c 5a a5 3c 52
```
