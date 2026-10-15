//! DNS framing: canonical base32 query names, payload budgets, tunnel and
//! non-tunnel answers (§7, A.2). Incoming messages are validated with the
//! `domain` crate; tunnel responses use a fixed-layout writer so the question
//! is echoed byte for byte.

use std::fmt;

use domain::base::Message;
use domain::base::iana::{Opcode, Rcode, Rtype};
use domain::rdata::Txt;

use crate::wire::{
    CLIENT_HEADER_LEN, MAX_SEGMENT_PAYLOAD, SEGMENT_OVERHEAD, SERVER_HEADER_LEN, STREAM_ACK_LEN,
};

pub const MAX_RESPONSE: usize = 512;
const MAX_NAME: usize = 255;
const MAX_LABEL: usize = 63;
const HEADER_LEN: usize = 12;
/// Answer NAME pointer, TYPE, CLASS, TTL, and RDLENGTH.
const ANSWER_FIXED: usize = 12;
const OPT_LEN: usize = 11;
const OPT_RECORD: [u8; OPT_LEN] = [0, 0x00, 0x29, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];
const TYPE_TXT: u16 = 16;
const TYPE_SOA: u16 = 6;
const CLASS_IN: u16 = 1;
const RCODE_REFUSED: u16 = 5;

/// The authenticated COOKIE_ECHO query and largest handshake response must fit.
const LARGEST_HANDSHAKE_QUERY: usize = CLIENT_HEADER_LEN + 2 + 52 + crate::crypto::PROOF_LEN;
const HELLO_QUERY: usize = CLIENT_HEADER_LEN + 2 + 16;
const LARGEST_HANDSHAKE_RESPONSE: usize = SERVER_HEADER_LEN + 2 + 40;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in data {
        acc = acc << 8 | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[(acc >> bits & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[(acc << (5 - bits) & 31) as usize] as char);
    }
    out
}

/// Decode unpadded base32 in either case, rejecting non-canonical input:
/// impossible lengths and nonzero unused trailing bits.
pub fn base32_decode(chars: &[u8]) -> Option<Vec<u8>> {
    if matches!(chars.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in chars {
        let value = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = acc << 5 | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

/// The delegated tunnel domain, lowercased.
#[derive(Debug, Clone)]
pub struct TunnelDomain {
    name: String,
    labels: Vec<Vec<u8>>,
    wire: Vec<u8>,
}

impl TunnelDomain {
    pub fn parse(input: &str) -> Result<TunnelDomain, String> {
        let name = input
            .strip_suffix('.')
            .unwrap_or(input)
            .to_ascii_lowercase();
        if name.is_empty() {
            return Err("tunnel domain is empty".into());
        }
        let mut labels = Vec::new();
        let mut wire = Vec::new();
        for label in name.split('.') {
            let ok_chars = label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
            if label.is_empty() || label.len() > MAX_LABEL || !ok_chars {
                return Err(format!("invalid label {label:?} in tunnel domain"));
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
            labels.push(label.as_bytes().to_vec());
        }
        wire.push(0);
        if wire.len() > MAX_NAME {
            return Err("tunnel domain is too long".into());
        }
        Ok(TunnelDomain { name, labels, wire })
    }

    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Segment sizes and query limits for this domain (§7.2).
    pub fn sizes(&self) -> Result<Sizes, String> {
        let dw = self.wire.len();
        let mut max_query = 0;
        while qname_len(max_query + 1, dw) <= MAX_NAME {
            max_query += 1;
        }
        let worst_response = response_capacity(question_len(max_query, dw));
        let u = max_query.saturating_sub(CLIENT_HEADER_LEN + STREAM_ACK_LEN + SEGMENT_OVERHEAD);
        let mut d = worst_response
            .saturating_sub(SERVER_HEADER_LEN + STREAM_ACK_LEN + SEGMENT_OVERHEAD)
            .min(MAX_SEGMENT_PAYLOAD);
        let poll_response = response_capacity(question_len(CLIENT_HEADER_LEN + STREAM_ACK_LEN, dw));
        let poll_segment_room = poll_response.saturating_sub(SERVER_HEADER_LEN + STREAM_ACK_LEN);
        if poll_segment_room < 2 * (SEGMENT_OVERHEAD + d) {
            d = (poll_segment_room / 2).saturating_sub(SEGMENT_OVERHEAD);
        }
        let u = u.min(MAX_SEGMENT_PAYLOAD);
        let handshake_fits = max_query >= LARGEST_HANDSHAKE_QUERY
            && response_capacity(question_len(HELLO_QUERY, dw)) >= LARGEST_HANDSHAKE_RESPONSE
            && response_capacity(question_len(LARGEST_HANDSHAKE_QUERY, dw))
                >= LARGEST_HANDSHAKE_RESPONSE;
        if u < 16 || d < 16 || !handshake_fits {
            return Err(format!(
                "tunnel domain {} leaves too little room for tunnel payload",
                self.name
            ));
        }
        Ok(Sizes {
            u,
            d,
            max_query_envelope: max_query,
            max_data_streams: (worst_response - SERVER_HEADER_LEN) / STREAM_ACK_LEN,
        })
    }
}

impl fmt::Display for TunnelDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizes {
    /// Upload SEGMENT payload size.
    pub u: usize,
    /// Download SEGMENT payload size.
    pub d: usize,
    /// Largest envelope a query name can carry.
    pub max_query_envelope: usize,
    /// Streams whose mandatory STREAM_ACKs fit in any response.
    pub max_data_streams: usize,
}

/// Wire length of the query name carrying an envelope of `envelope_len` bytes.
pub fn qname_len(envelope_len: usize, domain_wire_len: usize) -> usize {
    let chars = (envelope_len * 8).div_ceil(5);
    chars + chars.div_ceil(MAX_LABEL) + domain_wire_len
}

fn question_len(envelope_len: usize, domain_wire_len: usize) -> usize {
    qname_len(envelope_len, domain_wire_len) + 4
}

/// Envelope bytes available in a response to a question of `question_len`
/// bytes. Always budgets the server's OPT record, so a duplicate query that
/// differs only in EDNS cannot push a cached envelope past 512 bytes.
pub fn response_capacity(question_len: usize) -> usize {
    let avail = MAX_RESPONSE.saturating_sub(HEADER_LEN + question_len + ANSWER_FIXED + OPT_LEN);
    let mut envelope = avail;
    while envelope > 0 && envelope + envelope.div_ceil(255) > avail {
        envelope -= 1;
    }
    envelope
}

/// A client query ready to send, and its name for response matching.
#[derive(Debug, Clone)]
pub struct BuiltQuery {
    pub packet: Vec<u8>,
    /// Lowercase dotted query name, without the trailing dot.
    pub qname: String,
}

/// Build a TXT query carrying the wire envelope (public handshake or ciphertext).
pub fn build_query(id: u16, payload: &[u8], domain: &TunnelDomain) -> Option<BuiltQuery> {
    let chars = base32_encode(payload);
    if qname_len(payload.len(), domain.wire.len()) > MAX_NAME {
        return None;
    }
    let mut packet = Vec::with_capacity(HEADER_LEN + MAX_NAME + 4 + OPT_LEN);
    for word in [id, 0x0100, 1, 0, 0, 1] {
        packet.extend_from_slice(&word.to_be_bytes());
    }
    let mut qname =
        String::with_capacity(chars.len() + chars.len() / MAX_LABEL + domain.name.len() + 1);
    for label in chars.as_bytes().chunks(MAX_LABEL) {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        qname.push_str(std::str::from_utf8(label).expect("base32 is ASCII"));
        qname.push('.');
    }
    qname.push_str(&domain.name);
    packet.extend_from_slice(&domain.wire);
    packet.extend_from_slice(&TYPE_TXT.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    packet.extend_from_slice(&OPT_RECORD);
    Some(BuiltQuery { packet, qname })
}

/// An incoming query, validated by the DNS library, with its raw question.
#[derive(Debug)]
pub struct Query<'a> {
    pub id: u16,
    rd: bool,
    has_opt: bool,
    /// The question section exactly as received (name, type, class).
    question: &'a [u8],
    /// Offset in the packet and length of each question-name label.
    labels: Vec<(usize, usize)>,
    packet: &'a [u8],
    qtype: u16,
    qclass: u16,
}

/// Parse a DNS query for the authoritative server. Returns `None` for
/// anything that is not a well-formed standard query with one question.
pub fn parse_query(packet: &[u8]) -> Option<Query<'_>> {
    let msg = Message::from_octets(packet).ok()?;
    let header = msg.header();
    if header.qr() || header.opcode() != Opcode::QUERY || msg.header_counts().qdcount() != 1 {
        return None;
    }
    validate_sections(&msg)?;
    let has_opt = msg.opt().is_some();

    // Walk the question name ourselves: it must be echoed byte for byte.
    let mut pos = HEADER_LEN;
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len > MAX_LABEL || pos + 1 + len > packet.len() {
            return None; // compression pointers have no place in a question here
        }
        labels.push((pos + 1, len));
        pos += 1 + len;
    }
    if pos - HEADER_LEN > MAX_NAME || pos + 4 > packet.len() {
        return None;
    }
    let read16 = |at: usize| u16::from_be_bytes([packet[at], packet[at + 1]]);
    Some(Query {
        id: header.id(),
        rd: header.rd(),
        has_opt,
        question: &packet[HEADER_LEN..pos + 4],
        labels,
        packet,
        qtype: read16(pos),
        qclass: read16(pos + 2),
    })
}

fn validate_sections(msg: &Message<&[u8]>) -> Option<()> {
    let mut section = msg.answer().ok()?;
    loop {
        for record in &mut section {
            record.ok()?;
        }
        match section.next_section().ok()? {
            Some(next) => section = next,
            None => return Some(()),
        }
    }
}

impl Query<'_> {
    fn label(&self, i: usize) -> &[u8] {
        let (at, len) = self.labels[i];
        &self.packet[at..at + len]
    }

    /// The number of labels before the tunnel domain, if the name is in zone.
    pub fn zone_prefix(&self, domain: &TunnelDomain) -> Option<usize> {
        let k = domain.labels.len();
        let prefix = self.labels.len().checked_sub(k)?;
        (0..k)
            .all(|i| {
                self.label(prefix + i)
                    .eq_ignore_ascii_case(&domain.labels[i])
            })
            .then_some(prefix)
    }

    /// Wire bytes of a decodable tunnel query, per A.2: TXT, IN,
    /// canonical base32 labels, and at least a client header's worth.
    pub fn tunnel_payload(&self, prefix: usize) -> Option<Vec<u8>> {
        if self.qtype != TYPE_TXT || self.qclass != CLASS_IN || prefix == 0 {
            return None;
        }
        let mut chars = Vec::with_capacity(prefix * MAX_LABEL);
        for i in 0..prefix {
            let label = self.label(i);
            if i + 1 < prefix && label.len() != MAX_LABEL {
                return None;
            }
            chars.extend_from_slice(label);
        }
        base32_decode(&chars).filter(|bytes| bytes.len() >= CLIENT_HEADER_LEN)
    }

    pub fn question_len(&self) -> usize {
        self.question.len()
    }

    fn header(&self, rcode: u16, authoritative: bool, an: u16, ns: u16) -> Vec<u8> {
        let mut flags = 0x8000 | rcode;
        if authoritative {
            flags |= 0x0400;
        }
        if self.rd {
            flags |= 0x0100;
        }
        let mut out = Vec::with_capacity(MAX_RESPONSE);
        for word in [self.id, flags, 1, an, ns, u16::from(self.has_opt)] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.extend_from_slice(self.question);
        out
    }

    fn finish(&self, mut out: Vec<u8>) -> Vec<u8> {
        if self.has_opt {
            out.extend_from_slice(&OPT_RECORD);
        }
        out
    }

    /// The tunnel answer: one TXT record holding the wire envelope. `None`
    /// if it would exceed 512 bytes, which is an internal error.
    pub fn tunnel_response(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let mut out = self.header(0, true, 1, 0);
        let rdata_len = payload.len() + payload.len().div_ceil(255);
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_TXT.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata_len).ok()?.to_be_bytes());
        for chunk in payload.chunks(255) {
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
        let out = self.finish(out);
        (out.len() <= MAX_RESPONSE).then_some(out)
    }

    /// REFUSED for names outside the tunnel domain.
    pub fn refused(&self) -> Vec<u8> {
        self.finish(self.header(RCODE_REFUSED, false, 0, 0))
    }

    /// The minimal authoritative answer for an in-zone name that is not a
    /// tunnel query: the SOA at the apex, otherwise NODATA with the SOA in
    /// the authority section. Never NXDOMAIN.
    pub fn non_tunnel_answer(&self, prefix: usize) -> Vec<u8> {
        let apex_soa = prefix == 0 && self.qtype == TYPE_SOA && self.qclass == CLASS_IN;
        let (an, ns) = if apex_soa { (1, 0) } else { (0, 1) };
        let mut out = self.header(0, true, an, ns);
        // Compress the zone apex to its position in the question name.
        let apex = (self.labels[prefix].0 - 1) as u16 | 0xc000;
        let apex = apex.to_be_bytes();
        out.extend_from_slice(&apex);
        out.extend_from_slice(&TYPE_SOA.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&35u16.to_be_bytes());
        out.extend_from_slice(&apex);
        out.push(10);
        out.extend_from_slice(b"hostmaster");
        out.extend_from_slice(&apex);
        for value in [1u32, 3600, 600, 86400, 0] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        self.finish(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// A well-formed response with a non-NOERROR RCODE.
    Rcode,
    Malformed,
}

/// Check a resolver response against the query name sent and return the
/// concatenated TXT character strings (the wire envelope).
pub fn parse_response(packet: &[u8], qname: &str) -> Result<Vec<u8>, ResponseError> {
    use ResponseError::Malformed;
    let msg = Message::from_octets(packet).map_err(|_| Malformed)?;
    let header = msg.header();
    if !header.qr() || header.tc() {
        return Err(Malformed);
    }
    if header.rcode() != Rcode::NOERROR {
        return Err(ResponseError::Rcode);
    }
    let question = msg.sole_question().map_err(|_| Malformed)?;
    if !name_eq(question.qname(), qname) || question.qtype() != Rtype::TXT {
        return Err(Malformed);
    }
    let mut found = None;
    let mut count = 0;
    for record in msg.answer().map_err(|_| Malformed)?.limit_to::<Txt<_>>() {
        let record = record.map_err(|_| Malformed)?;
        if name_eq(record.owner(), qname) {
            count += 1;
            found = Some(record.data().iter().flatten().copied().collect::<Vec<u8>>());
        }
    }
    match (count, found) {
        (1, Some(envelope)) => Ok(envelope),
        _ => Err(Malformed),
    }
}

fn name_eq(name: impl fmt::Display, expected: &str) -> bool {
    let name = name.to_string();
    name.strip_suffix('.')
        .unwrap_or(&name)
        .eq_ignore_ascii_case(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Direction, Envelope, Frame, StreamAck};

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn domain() -> TunnelDomain {
        TunnelDomain::parse("t.example.com").unwrap()
    }

    fn encrypted(env: &Envelope) -> Vec<u8> {
        let mut data = env.encode();
        let dir = if env.rx_lag.is_some() {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        crate::crypto::fixture_keys().apply(&mut data, dir).unwrap();
        data
    }

    const SESSION: u32 = 0x01020304;

    fn v1_query() -> BuiltQuery {
        build_query(
            0x1234,
            &encrypted(&Envelope::client(SESSION, 5, 1, vec![])),
            &domain(),
        )
        .unwrap()
    }

    #[test]
    fn domain_wire_form() {
        assert_eq!(
            domain().wire(),
            hex("01 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00")
        );
        assert_eq!(
            TunnelDomain::parse("T.Example.COM.").unwrap().wire(),
            domain().wire()
        );
        assert!(TunnelDomain::parse("").is_err());
        assert!(TunnelDomain::parse("a..b").is_err());
        assert!(TunnelDomain::parse(&"a".repeat(64)).is_err());
    }

    #[test]
    fn base32_canonical() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let encoded = base32_encode(&data);
            assert_eq!(base32_decode(encoded.as_bytes()).unwrap(), data);
            assert_eq!(
                base32_decode(encoded.to_ascii_uppercase().as_bytes()).unwrap(),
                data
            );
        }
        assert_eq!(base32_decode(b"a"), None, "length 1 mod 8");
        assert_eq!(base32_decode(b"aaa"), None, "length 3 mod 8");
        assert_eq!(base32_decode(b"aaaaaa"), None, "length 6 mod 8");
        assert_eq!(base32_decode(b"ab"), None, "nonzero unused bits");
        assert_eq!(base32_decode(b"aa"), Some(vec![0]));
        assert_eq!(base32_decode(b"a1"), None, "outside alphabet");
    }

    #[test]
    fn v1_query_bytes() {
        let query = v1_query();
        assert_eq!(query.qname, "iaaqeayeaaaaabiz.t.example.com");
        assert_eq!(
            query.packet,
            hex("12 34 01 00 00 01 00 00 00 00 00 01 10 69 61 61
                 71 65 61 79 65 61 61 61 61 61 62 69 7a 01 74 07
                 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 10 00 01
                 00 00 29 04 d0 00 00 00 00 00 00")
        );
    }

    #[test]
    fn v2_and_v6_query_names() {
        let ack = |n, sack, delta| {
            Frame::StreamAck(StreamAck {
                stream: 1,
                next_expected: n,
                sack,
                credit_delta: delta,
            })
        };
        let v2 = Envelope::client(
            SESSION,
            6,
            1,
            vec![
                ack(3, 2, 30),
                Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: b"hello".to_vec(),
                },
            ],
        );
        assert_eq!(
            build_query(1, &encrypted(&v2), &domain()).unwrap().qname,
            "iaaqeayeaaaaabvwlowso2igezgmstqif2fajvxt2g5nzuoe4vy7cifn2lk7fj3.jky.t.example.com"
        );
        let v6 = Envelope::client(SESSION, 1000, 255, vec![ack(3, 2, 30)]);
        assert_eq!(
            build_query(1, &encrypted(&v6), &domain()).unwrap().qname,
            "iaaqeayeaaaah2huhk544rjw2saiq6rillghqlnxqm.t.example.com"
        );
    }

    #[test]
    fn v4_response_bytes() {
        let query = v1_query();
        let parsed = parse_query(&query.packet).unwrap();
        let prefix = parsed.zone_prefix(&domain()).unwrap();
        assert_eq!(prefix, 1);
        let payload = parsed.tunnel_payload(prefix).unwrap();
        assert_eq!(payload, encrypted(&Envelope::client(SESSION, 5, 1, vec![])));
        let response = parsed
            .tunnel_response(&encrypted(&Envelope::server(SESSION, 5, vec![])))
            .unwrap();
        assert_eq!(
            response,
            hex("12 34 85 00 00 01 00 01 00 00 00 01 10 69 61 61
                 71 65 61 79 65 61 61 61 61 61 62 69 7a 01 74 07
                 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 10 00 01
                 c0 0c 00 10 00 01 00 00 00 00 00 0a 09 40 01 02
                 03 04 00 00 00 05 00 00 29 04 d0 00 00 00 00 00
                 00")
        );
        assert_eq!(
            parse_response(&response, &query.qname).unwrap(),
            hex("40 01 02 03 04 00 00 00 05")
        );
    }

    #[test]
    fn worked_budget_example() {
        let sizes = domain().sizes().unwrap();
        assert_eq!(sizes.max_query_envelope, 147);
        assert_eq!(qname_len(147, 15), 255);
        assert_eq!(sizes.u, 111);
        assert_eq!(response_capacity(259), 217);
        assert_eq!(sizes.d, 182);
        let poll_frames = response_capacity(question_len(26, 15)) - SERVER_HEADER_LEN;
        assert_eq!(poll_frames, 404);
        assert_eq!(
            (poll_frames - STREAM_ACK_LEN) / (SEGMENT_OVERHEAD + sizes.d),
            2
        );
        assert_eq!(sizes.max_data_streams, 13);
    }

    #[test]
    fn full_budget_responses_fit_exactly() {
        let d = domain();
        let sizes = d.sizes().unwrap();
        let ack = Frame::StreamAck(StreamAck {
            stream: 1,
            next_expected: 0,
            sack: 0,
            credit_delta: 32,
        });
        let max_query = Envelope::client(
            SESSION,
            6,
            1,
            vec![
                ack.clone(),
                Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: vec![b'u'; sizes.u],
                },
            ],
        );
        assert_eq!(max_query.encoded_len(), 147);
        let built = build_query(7, &encrypted(&max_query), &d).unwrap();
        let parsed = parse_query(&built.packet).unwrap();
        assert_eq!(parsed.question_len(), 259);
        let mut response = Envelope::server(
            SESSION,
            6,
            vec![
                ack.clone(),
                Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: vec![b'd'; sizes.d],
                },
            ],
        );
        let packet = parsed.tunnel_response(&encrypted(&response)).unwrap();
        assert_eq!(packet.len(), 512);
        response.frames.push(Frame::SessionError { reason: 1 });
        assert!(
            parsed.tunnel_response(&encrypted(&response)).is_none(),
            "never exceeds 512"
        );
        // A two-string TXT envelope is reassembled in order.
        let poll = build_query(
            8,
            &encrypted(&Envelope::client(SESSION, 7, 1, vec![ack.clone()])),
            &d,
        )
        .unwrap();
        let parsed = parse_query(&poll.packet).unwrap();
        let seg = |seq, b| Frame::Segment {
            stream: 1,
            seq,
            payload: vec![b; sizes.d],
        };
        let two = Envelope::server(SESSION, 7, vec![ack, seg(0, b'a'), seg(1, b'b')]);
        let packet = parsed.tunnel_response(&encrypted(&two)).unwrap();
        assert_eq!(packet.len(), 508);
        assert_eq!(
            parse_response(&packet, &poll.qname).unwrap(),
            encrypted(&two)
        );
    }

    #[test]
    fn long_domains() {
        // Exactly enough room is accepted; one label more is rejected.
        let mut name = String::from("t");
        loop {
            let next = format!("x.{name}");
            match TunnelDomain::parse(&next) {
                Ok(d) if d.sizes().is_ok() => name = next,
                _ => break,
            }
        }
        let longest = TunnelDomain::parse(&name).unwrap();
        let sizes = longest.sizes().unwrap();
        assert!(sizes.u >= 16 && sizes.d >= 16);
        assert!(
            TunnelDomain::parse(&format!("{}.{}", "a".repeat(63), "b".repeat(32)))
                .unwrap()
                .sizes()
                .is_ok()
        );
        // v2's 32-byte authentication proof must fit even when data segments
        // still have room. A domain accepted by v1 can now be too long.
        assert!(
            TunnelDomain::parse(&format!("{}.{}", "a".repeat(63), "b".repeat(33)))
                .unwrap()
                .sizes()
                .is_err()
        );
        let near_max = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63));
        assert!(TunnelDomain::parse(&near_max).unwrap().sizes().is_err());
    }

    fn raw_query(name: &[&str], qtype: u16, opt: bool) -> Vec<u8> {
        let mut packet = Vec::new();
        for word in [0xbeefu16, 0x0100, 1, 0, 0, u16::from(opt)] {
            packet.extend_from_slice(&word.to_be_bytes());
        }
        for label in name {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        if opt {
            packet.extend_from_slice(&OPT_RECORD);
        }
        packet
    }

    fn rcode_and_counts(packet: &[u8]) -> (u16, [u16; 4]) {
        let word = |i: usize| u16::from_be_bytes([packet[i], packet[i + 1]]);
        (word(2), [word(4), word(6), word(8), word(10)])
    }

    #[test]
    fn non_tunnel_answers() {
        let d = domain();
        // Outside the zone: REFUSED.
        let packet = raw_query(&["www", "example", "org"], 1, false);
        let q = parse_query(&packet).unwrap();
        assert_eq!(q.zone_prefix(&d), None);
        assert_eq!(rcode_and_counts(&q.refused()), (0x8105, [1, 0, 0, 0]));

        // Apex SOA, with 0x20 case echoed and OPT returned.
        let packet = raw_query(&["T", "eXample", "com"], TYPE_SOA, true);
        let q = parse_query(&packet).unwrap();
        assert_eq!(q.zone_prefix(&d), Some(0));
        let answer = q.non_tunnel_answer(0);
        assert_eq!(rcode_and_counts(&answer), (0x8500, [1, 1, 0, 1]));
        assert_eq!(
            &answer[12..12 + q.question_len()],
            &packet[12..12 + q.question_len()]
        );
        let msg = Message::from_octets(answer.as_slice()).unwrap();
        let soa = msg
            .answer()
            .unwrap()
            .limit_to::<domain::rdata::Soa<_>>()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            soa.owner().to_string().to_ascii_lowercase(),
            "t.example.com"
        );
        assert_eq!(
            soa.data().rname().to_string().to_ascii_lowercase(),
            "hostmaster.t.example.com"
        );
        assert_eq!(soa.ttl().as_secs(), 0);

        // Partial names, apex NS, A queries, and undecodable TXT: NODATA.
        for (name, qtype) in [
            (&["pksd", "t", "example", "com"][..], 1),
            (&["t", "example", "com"][..], 2),
            (&["xyz1", "t", "example", "com"][..], TYPE_TXT),
            (&["a", "t", "example", "com"][..], TYPE_TXT),
        ] {
            let packet = raw_query(name, qtype, false);
            let q = parse_query(&packet).unwrap();
            let prefix = q.zone_prefix(&d).unwrap();
            assert!(q.tunnel_payload(prefix).is_none());
            let answer = q.non_tunnel_answer(prefix);
            assert_eq!(
                rcode_and_counts(&answer),
                (0x8500, [1, 0, 1, 0]),
                "{name:?}"
            );
            let msg = Message::from_octets(answer.as_slice()).unwrap();
            let auth = msg
                .authority()
                .unwrap()
                .limit_to::<domain::rdata::Soa<_>>()
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(
                auth.owner().to_string().to_ascii_lowercase(),
                "t.example.com"
            );
        }
    }

    #[test]
    fn tunnel_names_are_canonical() {
        let d = domain();
        let env = encrypted(&Envelope::client(
            SESSION,
            6,
            1,
            vec![Frame::Segment {
                stream: 1,
                seq: 0,
                payload: vec![0; 60],
            }],
        ));
        let query = build_query(1, &env, &d).unwrap();
        let mut upper = query.packet.clone();
        upper[13..20].make_ascii_uppercase();
        let q = parse_query(&upper).unwrap();
        assert_eq!(q.tunnel_payload(q.zone_prefix(&d).unwrap()).unwrap(), env);
        // Re-split the same characters into a short first label: rejected.
        let chars = base32_encode(&env);
        let (a, b) = chars.split_at(10);
        let mut labels: Vec<&str> = vec![a];
        labels.extend(
            b.as_bytes()
                .chunks(63)
                .map(|c| std::str::from_utf8(c).unwrap()),
        );
        labels.extend(["t", "example", "com"]);
        let packet = raw_query(&labels, TYPE_TXT, true);
        let q = parse_query(&packet).unwrap();
        assert!(q.tunnel_payload(q.zone_prefix(&d).unwrap()).is_none());
    }

    #[test]
    fn response_checks() {
        let query = v1_query();
        let parsed = parse_query(&query.packet).unwrap();
        let good = parsed
            .tunnel_response(&[1, 2, 3, 4, 5, 6, 7, 8, 9])
            .unwrap();
        // Case changes in the echoed name are accepted.
        let mut cased = good.clone();
        cased[13..16].make_ascii_uppercase();
        assert!(parse_response(&cased, &query.qname).is_ok());
        assert_eq!(
            parse_response(&good, "other.t.example.com"),
            Err(ResponseError::Malformed)
        );
        let mut tc = good.clone();
        tc[2] |= 0x02;
        assert_eq!(
            parse_response(&tc, &query.qname),
            Err(ResponseError::Malformed)
        );
        let mut servfail = good.clone();
        servfail[3] = (servfail[3] & 0xf0) | 2;
        assert_eq!(
            parse_response(&servfail, &query.qname),
            Err(ResponseError::Rcode)
        );
        let nodata = parsed.non_tunnel_answer(1);
        assert_eq!(
            parse_response(&nodata, &query.qname),
            Err(ResponseError::Malformed)
        );
        for n in 0..good.len() {
            let _ = parse_response(&good[..n], &query.qname);
            let _ = parse_query(&query.packet[..n.min(query.packet.len())]);
        }
    }
}
