#!/usr/bin/env python3
"""Generate DESIGN.md A.7 and check its wire/state regression vectors.

Standard library only. Run normally to print Markdown; --check verifies that
DESIGN.md contains that exact output. The small state models below are vector
oracles, not a transport implementation (no sockets, clocks, or TCP I/O).
"""

import argparse
import base64
import hashlib
import hmac
from pathlib import Path
import struct

DOMAIN = ["t", "example", "com"]
SESSION_ID = 0x01020304
KEY = bytes.fromhex("5a a5 3c")
SECRET = bytes(range(32))
CLIENT_NONCE = bytes(range(16))
SERVER_NONCE = bytes(range(16, 32))
NOW = 1700000000
EXPIRY = NOW + 30
U, D = 111, 182
WINDOW = 32
MAX_U32 = 0xffffffff
OPT = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)


def expect(actual, expected):
    if actual != expected:
        raise AssertionError(f"{actual!r} != {expected!r}")


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def b32(data):
    return base64.b32encode(data).decode().rstrip("=").lower()


def labels(chars):
    return [chars[i:i + 63] for i in range(0, len(chars), 63)]


def wire_name(name_labels):
    return b"".join(bytes([len(s)]) + s.encode("ascii") for s in name_labels) + b"\x00"


def xor(data, key=KEY):
    if not key:
        raise ValueError("empty XOR key")
    return bytes(value ^ key[i % len(key)] for i, value in enumerate(data))


def qname(envelope):
    return ".".join(labels(b32(xor(envelope))) + DOMAIN)


def hexdump(data):
    return "\n".join(data[i:i + 16].hex(" ") for i in range(0, len(data), 16))


def frame(kind, body):
    return struct.pack(">BB", kind, len(body)) + body


def client(exchange, lag, frames=b"", session=SESSION_ID):
    return struct.pack(">BIIB", 0x20, session, exchange, lag) + frames


def server(exchange, frames=b"", session=SESSION_ID):
    return struct.pack(">BII", 0x20, session, exchange) + frames


def ack(stream, next_expected, sack, delta):
    return frame(0x12, struct.pack(">IIIH", stream, next_expected, sack, delta))


def segment(stream, seq, payload):
    return frame(0x10, struct.pack(">II", stream, seq) + payload)


def fin(stream, seq):
    return frame(0x11, struct.pack(">II", stream, seq))


def question(envelope):
    return wire_name(qname(envelope).split(".")) + struct.pack(">HH", 16, 1)


def dns_query(envelope):
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1) + question(envelope) + OPT


def dns_response(query_envelope, response_envelope):
    encoded = xor(response_envelope)
    rdata = b"".join(bytes([len(encoded[i:i + 255])]) + encoded[i:i + 255]
                     for i in range(0, len(encoded), 255))
    result = (struct.pack(">HHHHHH", 0x1234, 0x8500, 1, 1, 0, 1)
              + question(query_envelope) + b"\xc0\x0c"
              + struct.pack(">HHIH", 16, 1, 0, len(rdata)) + rdata + OPT)
    if len(result) > 512:
        raise ValueError("DNS response budget exceeded")
    return result


def cookie(expiry=EXPIRY, client_nonce=CLIENT_NONCE, server_nonce=SERVER_NONCE):
    tail = struct.pack(">IHH", expiry, U, D)
    message = (b"cloudyday v1 cookie" + b"\x01" + wire_name(DOMAIN)
               + client_nonce + server_nonce + tail)
    return struct.pack(">I", expiry) + hmac.new(SECRET, message, hashlib.sha256).digest()[:16]


def response_evidence(exchange, lag):
    if lag == 255:
        return None
    if not 1 <= lag <= 254 or lag >= exchange:
        raise ValueError("invalid rx_lag")
    return exchange - lag


class Receiver:
    """Finite trace oracle: retain receipt history separately from consumption."""

    def __init__(self):
        self.data = set()
        self.final = None
        self.consumed = 0
        self.shutdown = False

    def snapshot(self):
        received = self.data | ({self.final} if self.final is not None else set())
        n = 0
        while n in received:
            n += 1
        sack = sum(1 << i for i in range(32) if n + 1 + i in received)
        limit = max(self.consumed + WINDOW, n)
        return n, sack, limit - n

    def receive(self, seq, is_fin=False):
        n, _, delta = self.snapshot()
        if is_fin:
            if self.final is not None:
                if seq != self.final:
                    raise ValueError("conflicting FIN")
                return "duplicate"
            if any(s >= seq for s in self.data):
                raise ValueError("FIN conflicts with data")
            if seq > n + delta:
                return "unadmitted"
            self.final = seq
        else:
            if self.final is not None and seq >= self.final:
                raise ValueError("data at/after FIN")
            if seq in self.data:
                return "duplicate"
            if seq >= n + delta:
                return "unadmitted"
            self.data.add(seq)
        return "accepted"

    def consume(self, count):
        for _ in range(count):
            if self.consumed not in self.data:
                raise ValueError("noncontiguous consumption")
            self.consumed += 1
        if self.final == self.consumed:
            self.consumed += 1
            self.shutdown = True


class Sender:
    """Merge incoming ACK snapshots without regressing prior knowledge."""

    def __init__(self, sent):
        self.sent = sent  # All sequences in [0, sent) have been dispatched.
        self.cumulative = 0
        self.credit = WINDOW
        self.sacked = set()

    def apply(self, n, sack, delta):
        received = {n + 1 + i for i in range(32) if sack & (1 << i)}
        if n > self.sent or any(s >= self.sent for s in received) or n + delta > MAX_U32:
            raise ValueError("ACK covers unsent data or overflows")
        self.cumulative = max(self.cumulative, n)
        self.credit = max(self.credit, n + delta)
        self.sacked = {s for s in self.sacked | received if s >= self.cumulative}

    def snapshot(self):
        return self.cumulative, sorted(self.sacked), self.credit


class StreamIDs:
    """Bounded used-ID bitmap, independent of temporary response tombstones."""

    def __init__(self, width=64):
        self.width, self.high, self.bits = width, 0, 0
        self.active, self.tombstones = set(), set()

    def admit(self, stream, capacity=True):
        if not 1 <= stream <= MAX_U32:
            raise ValueError("invalid stream ID")
        if stream in self.active:
            return "active"
        if stream in self.tombstones:
            return "tombstone"
        if stream < max(1, self.high - self.width + 1):
            return "reset: old ID"
        if stream <= self.high and self.bits & (1 << (self.high - stream)):
            return "reset: used ID"
        if stream > self.high:
            shift = stream - self.high
            self.bits = 0 if shift >= self.width else (self.bits << shift) & ((1 << self.width) - 1)
            self.high = stream
        self.bits |= 1 << (self.high - stream)
        if not capacity:
            return "reset: resource limit"
        self.active.add(stream)
        return "new"

    def close(self, stream):
        self.active.remove(stream)
        self.tombstones.add(stream)


class Handshakes:
    """Cookie/cache oracle with deterministic session assignments for vectors."""

    def __init__(self, capacity=256):
        self.capacity, self.allocations = capacity, 0
        self.cache = {}

    def echo(self, body, exchange, now):
        cn, sn, supplied = body[:16], body[16:32], body[32:]
        if len(body) != 52:
            raise ValueError("bad COOKIE_ECHO length")
        expiry = struct.unpack(">I", supplied[:4])[0]
        valid = hmac.compare_digest(supplied, cookie(expiry, cn, sn))
        if not valid or now >= expiry:
            return server(exchange, frame(0x20, b"\x06"), session=0)
        self.cache = {key: entry for key, entry in self.cache.items() if entry[1] > now}
        if body not in self.cache:
            if len(self.cache) >= self.capacity:
                return server(exchange, frame(0x20, b"\x03"), session=0)
            self.cache[body] = (SESSION_ID + self.allocations, expiry)
            self.allocations += 1
        session, _ = self.cache[body]
        return server(exchange, frame(0x04, struct.pack(">I", session)), session=0)


def generate():
    sections = ["""### A.7 Test vectors

`python3 tools/gen_vectors.py` regenerates this section using only the Python
standard library. `python3 tools/gen_vectors.py --check` runs the vector
assertions and verifies that this section is current. These are codec examples
and small state-transition oracles, not substitutes for implementation tests.

Unless noted otherwise, use session `0x01020304`, domain `t.example.com`, and
XOR key `5a a5 3c`. `plain` means serialized bytes before XOR, never plaintext
on the wire. All query names and DNS packets below include required XOR.
"""]

    def emit(title, explanation, lines):
        sections.append(f"**{title}**\n\n{explanation}\n\n```text\n" + "\n".join(lines) + "\n```\n")

    def envelopes(name, raw, query=False):
        expect(xor(xor(raw)), raw)
        result = [f"{name} plain: {raw.hex(' ')}", f"{name} XOR:   {xor(raw).hex(' ')}"]
        if query:
            result.append(f"{name} qname: {qname(raw)}")
        return result

    rejects(lambda: xor(b"test", b""))
    poll = client(5, 1)
    expect(xor(poll).hex(), "7aa43e59a13c5aa5395b")
    expect(qname(poll), "pksd4wnbhrnkkok3.t.example.com")
    query = dns_query(poll)
    expect(len(query), 59)
    emit("V1: XOR client poll.", "Exchange 5, `rx_lag = 1`, no frames; DNS ID `0x1234`.",
         envelopes("poll", poll, True) + [f"DNS query ({len(query)} bytes):", hexdump(query)])

    mixed = client(6, 1, ack(1, 3, 2, 30) + segment(1, 0, b"hello"))
    expect(len(mixed), 41)
    emit("V2: STREAM_ACK and SEGMENT.",
         "ACK stream 1: next expected 3, SACK bit 1 (sequence 5), credit limit 33.\n"
         "SEGMENT stream 1: sequence 0, payload `hello`. The query spans two labels.",
         envelopes("mixed", mixed, True))

    challenge_cookie = cookie()
    hello = client(1, 255, frame(0x01, CLIENT_NONCE), session=0)
    challenge = server(1, frame(0x02, SERVER_NONCE + struct.pack(">HH", U, D) + challenge_cookie), session=0)
    echo_body = CLIENT_NONCE + SERVER_NONCE + challenge_cookie
    echo = client(2, 255, frame(0x03, echo_body), session=0)
    handshakes = Handshakes()
    accepted = handshakes.echo(echo_body, 2, NOW)
    expect((len(hello), len(challenge), len(echo), len(accepted)), (28, 51, 64, 15))
    emit("V3: cookie handshake, no peer authentication.",
         "All envelope session IDs are zero; ACCEPT assigns `0x01020304`. Use the\n"
         "recommended cookie construction with server secret bytes `00`–`1f`, client\n"
         "nonce `00`–`0f`, server nonce `10`–`1f`, expiry 1700000030, and U=111, D=182.\n"
         "The cookie HMAC is server-only; no envelope carries a MAC or token proof.",
         [f"cookie: {challenge_cookie.hex(' ')}"]
         + envelopes("HELLO", hello) + envelopes("CHALLENGE", challenge)
         + envelopes("COOKIE_ECHO", echo) + envelopes("ACCEPT", accepted))

    response = dns_response(poll, server(5))
    expect(len(response), 81)
    # Check the directional budgets and XOR across TXT character-string splits.
    max_query = client(6, 1, ack(1, 0, 0, 32) + segment(1, 0, b"u" * U))
    max_response = server(6, ack(1, 1, 0, 31) + segment(1, 0, b"d" * D))
    expect((len(max_query), len(question(max_query))), (147, 259))
    expect(len(dns_response(max_query, max_response)), 512)
    rejects(lambda: dns_response(max_query, max_response + b"\x00"))
    minimal_poll = client(7, 1, ack(1, 0, 0, 32))
    two_segments = server(7, ack(1, 1, 0, 31)
                          + segment(1, 0, b"a" * D) + segment(1, 1, b"b" * D))
    packet = dns_response(minimal_poll, two_segments)
    expect(len(packet), 508)
    rdata = packet[12 + len(question(minimal_poll)) + 12:-len(OPT)]
    expect((rdata[0], rdata[256]), (255, len(two_segments) - 255))
    expect(xor(rdata[1:256] + rdata[257:]), two_segments)
    emit("V4: DNS response to V1.",
         "Empty server envelope for exchange 5. XOR restarts at offset zero; TXT\n"
         "length octets and DNS framing are not XORed.",
         envelopes("response", server(5)) + [f"DNS response ({len(response)} bytes):", hexdump(response)])

    receiver = Receiver()
    for seq in range(32):
        expect(receiver.receive(seq), "accepted")
    expect(receiver.snapshot(), (32, 0, 0))
    expect(receiver.receive(32), "unadmitted")
    expect(receiver.receive(33, True), "unadmitted")
    expect(receiver.receive(32, True), "accepted")
    expect(receiver.snapshot(), (33, 0, 0))
    expect((len(receiver.data), receiver.consumed, receiver.shutdown), (32, 0, False))
    expect(receiver.receive(32, True), "duplicate")
    rejects(lambda: receiver.receive(32))
    rejects(lambda: receiver.receive(33))
    rejects(lambda: receiver.receive(31, True))
    receiver.consume(32)
    expect(receiver.shutdown, True)
    reordered = Receiver()
    expect(reordered.receive(32, True), "accepted")
    expect(reordered.snapshot(), (0, 0x80000000, 32))
    for seq in reversed(range(32)):
        reordered.receive(seq)
    expect(reordered.snapshot(), (33, 0, 0))
    expect(reordered.shutdown, False)
    emit("V5: full-window FIN and out-of-order FIN.",
         "For stream 1, retain all 32 data segments without consuming them. A FIN at\n"
         "sequence 32 is accepted without data credit. Receipt/ACK does not shut down\n"
         "TCP; only consumption of all preceding bytes does. ACK tuples below are\n"
         "`(next_expected, sack, credit_delta)`.",
         ["data 0..31 received, none consumed: (32, 0x00000000, 0)",
          "SEGMENT 32 / FIN 33: unadmitted",
          "FIN 32 received: (33, 0x00000000, 0); retained data=32; shutdown=false",
          "duplicate FIN 32: unchanged; data >=32 or conflicting FIN: protocol violation",
          "consume data 0..31: shutdown=true",
          "FIN 32 before any data: (0, 0x80000000, 32)",
          "then data 31..0: (33, 0x00000000, 0); shutdown=false"]
         + envelopes("FIN query", client(7, 1, fin(1, 32)))
         + envelopes("terminal ACK", server(7, ack(1, 33, 0, 0))))

    expect(response_evidence(1000, 254), 746)
    expect(response_evidence(1000, 255), None)
    expect(response_evidence(1001, 1), 1000)
    rejects(lambda: response_evidence(1000, 0))
    rejects(lambda: response_evidence(5, 5))
    lag_sender = Sender(6)
    lag_sender.apply(3, 2, 30)
    expect(lag_sender.snapshot(), (3, [5], 33))
    emit("V6: saturated lag does not establish delivery.",
         "At exchange 1000, both highest received response 700 and no response at all\n"
         "encode lag 255. Neither proves response 745 arrived. Explicit STREAM_ACKs\n"
         "still apply, and timeout recovery remains enabled.",
         ["exchange=1000 lag=254 -> exact highest=746",
          "exchange=1000 lag=255 -> highest=unknown; no new exchange-loss evidence",
          "same query ACK (3, 0x00000002, 30) -> cumulative=3, SACKed=[5], credit=33",
          "exchange=1001 lag=1 -> exact highest=1000",
          "lag=0 or exact lag >= exchange: invalid"]
         + envelopes("saturated query", client(1000, 255, ack(1, 3, 2, 30)), True))

    ids = StreamIDs()
    expect(ids.admit(1), "new")
    ids.close(1)
    expect(ids.admit(1), "tombstone")
    ids.tombstones.clear()  # Expiry or capacity eviction has the same effect.
    expect(ids.admit(1), "reset: used ID")
    expect(ids.admit(65), "new")
    expect(ids.admit(1), "reset: old ID")
    expect(ids.admit(2), "new")
    expect(ids.admit(3, capacity=False), "reset: resource limit")
    expect(ids.admit(3), "reset: used ID")
    expect(ids.admit(129), "new")
    expect(ids.admit(2), "active")
    expect(ids.bits.bit_length() <= 64, True)
    rejects(lambda: ids.admit(0))
    shifted = StreamIDs()
    expect(shifted.admit(1), "new")
    shifted.close(1)
    shifted.tombstones.clear()
    expect(shifted.admit(2), "new")
    expect(shifted.admit(1), "reset: used ID")  # Sub-window shifts preserve bits.
    expect(shifted.admit(MAX_U32), "new")  # A huge jump must not allocate a huge bitmap.
    expect(shifted.bits, 1)
    opening = segment(1, 0, bytes.fromhex("01 cb 00 71 07 01 bb"))
    emit("V7: tombstone expiry/eviction never reopens a stream.",
         "Use a 64-ID window. Expiry and eviction remove only the response tombstone.\n"
         "Retransmit stream 1's OPEN for `203.0.113.7:443` under fresh exchange 11;\n"
         "the server must return RESET, not allocate or dial again.",
         ["admit 1 -> new; close 1 -> tombstone",
          "retry 1 with tombstone -> tombstone response",
          "remove tombstone; retry 1 -> RESET(0x06), used bit retained",
          "admit 65 -> window [2,65]; retry 1 -> RESET(0x06), too old",
          "admit unseen 2 -> new",
          "reject 3 for resource limit; retry 3 -> RESET(0x06), used bit retained",
          "admit 129 -> window [66,129]; traffic for active 2 -> existing stream"]
         + envelopes("late OPEN", client(11, 1, opening))
         + envelopes("RESET", server(11, frame(0x13, struct.pack(">IB", 1, 6)))))

    retry_echo = client(3, 255, frame(0x03, echo_body), session=0)
    retry_accept = handshakes.echo(echo_body, 3, NOW + 2)
    expect(retry_accept, server(3, frame(0x04, struct.pack(">I", SESSION_ID)), session=0))
    expect(handshakes.allocations, 1)
    tampered = echo_body[:-1] + bytes([echo_body[-1] ^ 1])
    error = server(4, frame(0x20, b"\x06"), session=0)
    expect(handshakes.echo(tampered, 4, NOW + 2), error)
    expired = handshakes.echo(echo_body, 4, EXPIRY)
    expect(expired, error)
    expect(handshakes.allocations, 1)
    limited = Handshakes(capacity=1)
    expect(limited.echo(echo_body, 2, NOW), accepted)
    other_nonce = bytes(reversed(CLIENT_NONCE))
    other_echo = other_nonce + SERVER_NONCE + cookie(client_nonce=other_nonce)
    expect(limited.echo(other_echo, 2, NOW), server(2, frame(0x20, b"\x03"), session=0))
    expect(limited.echo(echo_body, 3, NOW + 2), retry_accept)
    expect((limited.allocations, len(limited.cache)), (1, 1))
    emit("V8: lost ACCEPT, cookie validation, and retry identity.",
         "Drop V3's ACCEPT. Retry COOKIE_ECHO at exchange 3 with the identical body.\n"
         "Return the same assigned session but rebuild the envelope's exchange ID.\n"
         "A literal replay of exchange 2's ACCEPT must fail exchange-3 matching.",
         ["first ACCEPT dropped; retry -> allocations=1, assigned session=0x01020304",
          "tampered cookie with cached nonces -> SESSION_ERROR(0x06)",
          "now=1700000030 (exact expiry) -> SESSION_ERROR(0x06), allocations still 1",
          "full handshake cache -> SESSION_ERROR(0x03), no live-entry eviction"]
         + envelopes("retry COOKIE_ECHO", retry_echo)
         + envelopes("retry ACCEPT", retry_accept)
         + envelopes("expired", expired))

    sender = Sender(12)
    sender.apply(3, 2, 29)
    expect(sender.snapshot(), (3, [5], 32))
    sender.apply(6, 2, 30)
    expect(sender.snapshot(), (6, [8], 36))
    sender.apply(3, 2, 29)
    expect(sender.snapshot(), (6, [8], 36))
    sender.apply(4, 0x09, 28)  # Earlier snapshot retained sequences 5 and 8.
    expect(sender.snapshot(), (6, [8], 36))
    rejects(lambda: sender.apply(13, 0, 32))
    rejects(lambda: sender.apply(6, 0x20, 30))  # SACK sequence 12 was never sent.
    overflow = Sender(MAX_U32)
    rejects(lambda: overflow.apply(MAX_U32, 0, 1))
    blocked = Sender(32)
    blocked.apply(32, 0, 0)
    receiver = Receiver()
    for seq in range(32):
        receiver.receive(seq)
    receiver.consume(8)
    expect(receiver.snapshot(), (32, 0, 8))
    expect(blocked.credit, 32)  # First credit update is lost.
    blocked.apply(*receiver.snapshot())  # Periodic repeat repairs the loss.
    expect(blocked.credit, 40)
    blocked.apply(32, 0, 0)  # A stale ACK must not close the window again.
    expect(blocked.credit, 40)
    emit("V9: reordered ACKs and lost credit updates.",
         "ACK tuples are `(next_expected, sack, credit_delta)`; merged state is\n"
         "`(cumulative, absolute SACKed sequences, credit limit)`. Sequences 0–11\n"
         "have been sent for the reorder trace. Interpret each SACK against its own\n"
         "ACK base and retain positive evidence from older ACKs.",
         ["ACK (3, 0x00000002, 29) -> (3, [5], 32)",
          "ACK (6, 0x00000002, 30) -> (6, [8], 36)",
          "stale ACK (3, 0x00000002, 29) -> (6, [8], 36)",
          "older ACK (4, 0x00000009, 28) -> (6, [8], 36)",
          "ACK of unsent sequence or credit arithmetic overflow -> reject",
          "credit trace: send/receive 0..31, ACK (32,0,0) -> blocked at credit=32",
          "consume 0..7; drop ACK (32,0,8) -> sender still blocked",
          "repeat ACK (32,0,8) -> credit=40; new sequences 32..39 allowed, 40 blocked",
          "late ACK (32,0,0) -> credit remains 40"]
         + envelopes("credit repeat", server(12, ack(1, 32, 0, 8))))

    return "\n".join(sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify DESIGN.md A.7 instead of printing it")
    args = parser.parse_args()
    generated = generate()
    if args.check:
        design = Path(__file__).resolve().parents[1] / "DESIGN.md"
        marker = "### A.7 Test vectors\n"
        contents = design.read_text()
        if marker not in contents or marker + contents.split(marker, 1)[1] != generated:
            raise SystemExit("DESIGN.md A.7 is stale; regenerate with tools/gen_vectors.py")
        print("All wire/state vector assertions passed; DESIGN.md A.7 matches.")
    else:
        print(generated, end="")


if __name__ == "__main__":
    main()
