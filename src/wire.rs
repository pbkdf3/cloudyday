//! Bounded binary codecs: envelopes, frames, XOR, server cookies, and the
//! opening records carried at the start of each stream direction (Appendix A).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const VERSION: u8 = 1;
pub const FLAG_MORE_PENDING: u8 = 0x02;
const RESERVED_FLAGS: u8 = 0x1d;

pub const CLIENT_HEADER_LEN: usize = 10;
pub const SERVER_HEADER_LEN: usize = 9;
/// `kind` + `length` + `stream` + `seq`.
pub const SEGMENT_OVERHEAD: usize = 10;
pub const FIN_LEN: usize = 10;
pub const STREAM_ACK_LEN: usize = 16;
pub const RESET_LEN: usize = 7;
/// A frame body length is a `u8`, and SEGMENT spends 8 of it on stream and seq.
pub const MAX_SEGMENT_PAYLOAD: usize = 255 - 8;

pub const NONCE_LEN: usize = 16;
pub const COOKIE_LEN: usize = 20;
/// Receive window and initial credit, in frames.
pub const WINDOW: u32 = 32;
/// `rx_lag` value meaning "unknown or at least 255 behind".
pub const LAG_UNKNOWN: u8 = 255;
pub const MAX_OPEN_RECORD: usize = 512;

const COOKIE_LABEL: &[u8] = b"cloudyday v1 cookie";

pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const CHALLENGE: u8 = 0x02;
    pub const COOKIE_ECHO: u8 = 0x03;
    pub const ACCEPT: u8 = 0x04;
    pub const SEGMENT: u8 = 0x10;
    pub const FIN: u8 = 0x11;
    pub const STREAM_ACK: u8 = 0x12;
    pub const RESET: u8 = 0x13;
    pub const SESSION_ERROR: u8 = 0x20;
}

pub mod reset {
    pub const UNSPECIFIED: u8 = 0x00;
    pub const LOCAL_ABORT: u8 = 0x01;
    pub const STALLED: u8 = 0x02;
    pub const PROTOCOL: u8 = 0x03;
    pub const RESOURCE: u8 = 0x04;
    pub const OPEN_DEADLINE: u8 = 0x05;
    pub const UNKNOWN_STREAM: u8 = 0x06;
    pub const EXHAUSTED: u8 = 0x07;
}

pub mod session_error {
    pub const UNKNOWN_SESSION: u8 = 0x01;
    pub const UNSUPPORTED_VERSION: u8 = 0x02;
    pub const BUSY: u8 = 0x03;
    pub const HANDSHAKE_EXPIRED: u8 = 0x06;

    pub fn is_known(reason: u8) -> bool {
        matches!(
            reason,
            UNKNOWN_SESSION | UNSUPPORTED_VERSION | BUSY | HANDSHAKE_EXPIRED
        )
    }
}

/// SOCKS-compatible OPEN_RESULT status codes.
pub mod status {
    pub const SUCCEEDED: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    pub const NOT_ALLOWED: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const TIMED_OUT: u8 = 0x06;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The version bits are not 1; the server answers SESSION_ERROR.
    UnsupportedVersion,
    Malformed(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnsupportedVersion => f.write_str("unsupported protocol version"),
            WireError::Malformed(what) => write!(f, "malformed envelope: {what}"),
        }
    }
}

impl std::error::Error for WireError {}

fn malformed<T>(what: &'static str) -> Result<T, WireError> {
    Err(WireError::Malformed(what))
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn array<const N: usize>(b: &[u8]) -> [u8; N] {
    b[..N].try_into().expect("length checked by caller")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAck {
    pub stream: u32,
    pub next_expected: u32,
    pub sack: u32,
    pub credit_delta: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        client_nonce: [u8; NONCE_LEN],
    },
    Challenge {
        server_nonce: [u8; NONCE_LEN],
        u: u16,
        d: u16,
        cookie: [u8; COOKIE_LEN],
    },
    CookieEcho {
        client_nonce: [u8; NONCE_LEN],
        server_nonce: [u8; NONCE_LEN],
        cookie: [u8; COOKIE_LEN],
    },
    Accept {
        session_id: u32,
    },
    Segment {
        stream: u32,
        seq: u32,
        payload: Vec<u8>,
    },
    Fin {
        stream: u32,
        seq: u32,
    },
    StreamAck(StreamAck),
    Reset {
        stream: u32,
        reason: u8,
    },
    SessionError {
        reason: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Frame {
    fn kind(&self) -> u8 {
        match self {
            Frame::Hello { .. } => kind::HELLO,
            Frame::Challenge { .. } => kind::CHALLENGE,
            Frame::CookieEcho { .. } => kind::COOKIE_ECHO,
            Frame::Accept { .. } => kind::ACCEPT,
            Frame::Segment { .. } => kind::SEGMENT,
            Frame::Fin { .. } => kind::FIN,
            Frame::StreamAck(_) => kind::STREAM_ACK,
            Frame::Reset { .. } => kind::RESET,
            Frame::SessionError { .. } => kind::SESSION_ERROR,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            Frame::Hello { .. } => NONCE_LEN,
            Frame::Challenge { .. } => NONCE_LEN + 4 + COOKIE_LEN,
            Frame::CookieEcho { .. } => 2 * NONCE_LEN + COOKIE_LEN,
            Frame::Accept { .. } => 4,
            Frame::Segment { payload, .. } => 8 + payload.len(),
            Frame::Fin { .. } => 8,
            Frame::StreamAck(_) => 14,
            Frame::Reset { .. } => 5,
            Frame::SessionError { .. } => 1,
        }
    }

    pub fn encoded_len(&self) -> usize {
        2 + self.body_len()
    }

    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            Frame::Hello { .. }
                | Frame::Challenge { .. }
                | Frame::CookieEcho { .. }
                | Frame::Accept { .. }
        )
    }

    fn allowed(&self, dir: Direction) -> bool {
        match self {
            Frame::Hello { .. } | Frame::CookieEcho { .. } => dir == Direction::ClientToServer,
            Frame::Challenge { .. } | Frame::Accept { .. } | Frame::SessionError { .. } => {
                dir == Direction::ServerToClient
            }
            _ => true,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.body_len();
        assert!(len <= 255, "frame body exceeds u8 length");
        out.push(self.kind());
        out.push(len as u8);
        match self {
            Frame::Hello { client_nonce } => out.extend_from_slice(client_nonce),
            Frame::Challenge {
                server_nonce,
                u,
                d,
                cookie,
            } => {
                out.extend_from_slice(server_nonce);
                out.extend_from_slice(&u.to_be_bytes());
                out.extend_from_slice(&d.to_be_bytes());
                out.extend_from_slice(cookie);
            }
            Frame::CookieEcho {
                client_nonce,
                server_nonce,
                cookie,
            } => {
                out.extend_from_slice(client_nonce);
                out.extend_from_slice(server_nonce);
                out.extend_from_slice(cookie);
            }
            Frame::Accept { session_id } => out.extend_from_slice(&session_id.to_be_bytes()),
            Frame::Segment {
                stream,
                seq,
                payload,
            } => {
                out.extend_from_slice(&stream.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(payload);
            }
            Frame::Fin { stream, seq } => {
                out.extend_from_slice(&stream.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
            }
            Frame::StreamAck(ack) => {
                out.extend_from_slice(&ack.stream.to_be_bytes());
                out.extend_from_slice(&ack.next_expected.to_be_bytes());
                out.extend_from_slice(&ack.sack.to_be_bytes());
                out.extend_from_slice(&ack.credit_delta.to_be_bytes());
            }
            Frame::Reset { stream, reason } => {
                out.extend_from_slice(&stream.to_be_bytes());
                out.push(*reason);
            }
            Frame::SessionError { reason } => out.push(*reason),
        }
    }

    fn decode(kind: u8, body: &[u8]) -> Result<Frame, WireError> {
        let exact = |n: usize| {
            if body.len() == n {
                Ok(())
            } else {
                malformed("frame body length")
            }
        };
        Ok(match kind {
            kind::HELLO => {
                exact(NONCE_LEN)?;
                Frame::Hello {
                    client_nonce: array(body),
                }
            }
            kind::CHALLENGE => {
                exact(NONCE_LEN + 4 + COOKIE_LEN)?;
                Frame::Challenge {
                    server_nonce: array(body),
                    u: be16(&body[16..]),
                    d: be16(&body[18..]),
                    cookie: array(&body[20..]),
                }
            }
            kind::COOKIE_ECHO => {
                exact(2 * NONCE_LEN + COOKIE_LEN)?;
                Frame::CookieEcho {
                    client_nonce: array(body),
                    server_nonce: array(&body[16..]),
                    cookie: array(&body[32..]),
                }
            }
            kind::ACCEPT => {
                exact(4)?;
                Frame::Accept {
                    session_id: be32(body),
                }
            }
            kind::SEGMENT => {
                if body.len() < 9 {
                    return malformed("empty or short SEGMENT");
                }
                Frame::Segment {
                    stream: be32(body),
                    seq: be32(&body[4..]),
                    payload: body[8..].to_vec(),
                }
            }
            kind::FIN => {
                exact(8)?;
                Frame::Fin {
                    stream: be32(body),
                    seq: be32(&body[4..]),
                }
            }
            kind::STREAM_ACK => {
                exact(14)?;
                Frame::StreamAck(StreamAck {
                    stream: be32(body),
                    next_expected: be32(&body[4..]),
                    sack: be32(&body[8..]),
                    credit_delta: be16(&body[12..]),
                })
            }
            kind::RESET => {
                exact(5)?;
                Frame::Reset {
                    stream: be32(body),
                    reason: body[4],
                }
            }
            kind::SESSION_ERROR => {
                exact(1)?;
                if !session_error::is_known(body[0]) {
                    return malformed("unknown SESSION_ERROR reason");
                }
                Frame::SessionError { reason: body[0] }
            }
            _ => return malformed("unknown frame kind"),
        })
    }
}

/// A protocol envelope. `rx_lag` is present exactly on client-to-server
/// envelopes; `more_pending` is meaningful only from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub session_id: u32,
    pub exchange_id: u32,
    pub rx_lag: Option<u8>,
    pub more_pending: bool,
    pub frames: Vec<Frame>,
}

impl Envelope {
    pub fn client(session_id: u32, exchange_id: u32, rx_lag: u8, frames: Vec<Frame>) -> Self {
        Envelope {
            session_id,
            exchange_id,
            rx_lag: Some(rx_lag),
            more_pending: false,
            frames,
        }
    }

    pub fn server(session_id: u32, exchange_id: u32, frames: Vec<Frame>) -> Self {
        Envelope {
            session_id,
            exchange_id,
            rx_lag: None,
            more_pending: false,
            frames,
        }
    }

    pub fn header_len(&self) -> usize {
        if self.rx_lag.is_some() {
            CLIENT_HEADER_LEN
        } else {
            SERVER_HEADER_LEN
        }
    }

    pub fn encoded_len(&self) -> usize {
        self.header_len() + self.frames.iter().map(Frame::encoded_len).sum::<usize>()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        let flags = if self.more_pending {
            FLAG_MORE_PENDING
        } else {
            0
        };
        out.push(VERSION << 5 | flags);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.exchange_id.to_be_bytes());
        if let Some(lag) = self.rx_lag {
            out.push(lag);
        }
        for frame in &self.frames {
            frame.encode(&mut out);
        }
        out
    }

    /// Parse and validate an envelope travelling in `dir`, after XOR removal.
    pub fn decode(data: &[u8], dir: Direction) -> Result<Envelope, WireError> {
        let header_len = match dir {
            Direction::ClientToServer => CLIENT_HEADER_LEN,
            Direction::ServerToClient => SERVER_HEADER_LEN,
        };
        if data.len() < header_len {
            return malformed("short header");
        }
        if data[0] >> 5 != VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        let flags = data[0] & 0x1f;
        if flags & RESERVED_FLAGS != 0 {
            return malformed("reserved flags set");
        }
        let more_pending = flags & FLAG_MORE_PENDING != 0;
        if more_pending && dir == Direction::ClientToServer {
            return malformed("MORE_PENDING from client");
        }
        let session_id = be32(&data[1..]);
        let exchange_id = be32(&data[5..]);
        if exchange_id == 0 {
            return malformed("exchange ID zero");
        }
        let rx_lag = match dir {
            Direction::ClientToServer => {
                let lag = data[9];
                if lag == 0 || (lag != LAG_UNKNOWN && u32::from(lag) >= exchange_id) {
                    return malformed("invalid rx_lag");
                }
                Some(lag)
            }
            Direction::ServerToClient => None,
        };

        let mut frames = Vec::new();
        let mut rest = &data[header_len..];
        while !rest.is_empty() {
            if rest.len() < 2 {
                return malformed("truncated frame header");
            }
            let (kind, len) = (rest[0], rest[1] as usize);
            if rest.len() < 2 + len {
                return malformed("frame runs past envelope");
            }
            let frame = Frame::decode(kind, &rest[2..2 + len])?;
            if !frame.allowed(dir) {
                return malformed("frame not allowed in this direction");
            }
            frames.push(frame);
            rest = &rest[2 + len..];
        }

        let is_error = |f: &Frame| matches!(f, Frame::SessionError { .. });
        if frames.iter().any(is_error) && frames.len() != 1 {
            return malformed("SESSION_ERROR must travel alone");
        }
        if session_id == 0 {
            if frames.len() != 1 || !(frames[0].is_handshake() || is_error(&frames[0])) {
                return malformed("handshake envelope must carry one handshake frame");
            }
        } else if frames.iter().any(Frame::is_handshake) {
            return malformed("handshake frame in session envelope");
        }

        Ok(Envelope {
            session_id,
            exchange_id,
            rx_lag,
            more_pending,
            frames,
        })
    }
}

/// Session and exchange IDs from a header whose version may be unsupported.
pub fn peek_ids(data: &[u8]) -> Option<(u32, u32)> {
    (data.len() >= CLIENT_HEADER_LEN).then(|| (be32(&data[1..]), be32(&data[5..])))
}

/// The highest response exchange a client query proves was received, if any.
/// Lag 255 never establishes receipt.
pub fn response_evidence(exchange_id: u32, rx_lag: u8) -> Option<u32> {
    (rx_lag != LAG_UNKNOWN && rx_lag != 0 && u32::from(rx_lag) < exchange_id)
        .then(|| exchange_id - u32::from(rx_lag))
}

/// The shared repeating XOR key. Never printed.
#[derive(Clone)]
pub struct XorKey(Arc<[u8]>);

impl XorKey {
    pub fn new(bytes: Vec<u8>) -> Option<XorKey> {
        (!bytes.is_empty()).then(|| XorKey(bytes.into()))
    }

    /// XOR a complete envelope in place, starting at key offset zero.
    pub fn apply(&self, data: &mut [u8]) {
        for (byte, k) in data.iter_mut().zip(self.0.iter().cycle()) {
            *byte ^= k;
        }
    }
}

impl fmt::Debug for XorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XorKey(<{} bytes redacted>)", self.0.len())
    }
}

/// Server cookie inputs other than the secret and expiry.
pub struct CookieInput<'a> {
    pub domain_wire: &'a [u8],
    pub client_nonce: &'a [u8; NONCE_LEN],
    pub server_nonce: &'a [u8; NONCE_LEN],
    pub u: u16,
    pub d: u16,
}

impl CookieInput<'_> {
    fn mac(&self, secret: &[u8; 32], expiry: u32) -> Hmac<Sha256> {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(COOKIE_LABEL);
        mac.update(&[VERSION]);
        mac.update(self.domain_wire);
        mac.update(self.client_nonce);
        mac.update(self.server_nonce);
        mac.update(&expiry.to_be_bytes());
        mac.update(&self.u.to_be_bytes());
        mac.update(&self.d.to_be_bytes());
        mac
    }

    pub fn make(&self, secret: &[u8; 32], expiry: u32) -> [u8; COOKIE_LEN] {
        let tag = self.mac(secret, expiry).finalize().into_bytes();
        let mut cookie = [0; COOKIE_LEN];
        cookie[..4].copy_from_slice(&expiry.to_be_bytes());
        cookie[4..].copy_from_slice(&tag[..16]);
        cookie
    }

    /// Constant-time MAC check, then expiry (`now >= expiry` is expired).
    pub fn verify(&self, secret: &[u8; 32], cookie: &[u8; COOKIE_LEN], now_unix: u64) -> bool {
        let expiry = be32(cookie);
        let valid = self
            .mac(secret, expiry)
            .verify_truncated_left(&cookie[4..])
            .is_ok();
        valid && now_unix < u64::from(expiry)
    }
}

/// Destination host in an OPEN record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// OPEN: the first bytes of the client's direction of a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Domain(name) => write!(f, "{name}:{}", self.port),
        }
    }
}

/// Names may contain only ASCII letters, digits, `-`, `_`, and `.`.
pub fn valid_hostname(name: &[u8]) -> bool {
    (1..=255).contains(&name.len())
        && name
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn encode_ip(ip: IpAddr, out: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Parse `atyp | address` at the start of `buf`. `Ok(None)` means incomplete.
fn parse_host(buf: &[u8], allow_domain: bool) -> Result<Option<(Host, usize)>, WireError> {
    let Some(&atyp) = buf.first() else {
        return Ok(None);
    };
    let need = |n: usize| buf.len() >= n;
    match atyp {
        0x01 if need(5) => Ok(Some((
            Host::Ip(Ipv4Addr::from(array::<4>(&buf[1..])).into()),
            5,
        ))),
        0x04 if need(17) => Ok(Some((
            Host::Ip(Ipv6Addr::from(array::<16>(&buf[1..])).into()),
            17,
        ))),
        0x03 if allow_domain => {
            let Some(&len) = buf.get(1) else {
                return Ok(None);
            };
            let len = len as usize;
            if len == 0 {
                return malformed("empty destination name");
            }
            if !need(2 + len) {
                return Ok(None);
            }
            let name = &buf[2..2 + len];
            if !valid_hostname(name) {
                return malformed("invalid destination name");
            }
            let name = String::from_utf8(name.to_vec()).expect("validated ASCII");
            Ok(Some((Host::Domain(name), 2 + len)))
        }
        0x01 | 0x04 => Ok(None),
        _ => malformed("unknown address type"),
    }
}

impl Target {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 255);
        match &self.host {
            Host::Ip(ip) => encode_ip(*ip, &mut out),
            Host::Domain(name) => {
                assert!(valid_hostname(name.as_bytes()));
                out.push(0x03);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }

    /// Parse a record prefix: `Ok(None)` while incomplete, else the record
    /// and the number of bytes it used.
    pub fn parse(buf: &[u8]) -> Result<Option<(Target, usize)>, WireError> {
        let Some((host, used)) = parse_host(buf, true)? else {
            return Ok(None);
        };
        if buf.len() < used + 2 {
            return Ok(None);
        }
        Ok(Some((
            Target {
                host,
                port: be16(&buf[used..]),
            },
            used + 2,
        )))
    }
}

/// OPEN_RESULT: the first bytes of the server's direction of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenResult {
    pub status: u8,
    pub bound: SocketAddr,
}

impl OpenResult {
    pub fn failure(status: u8) -> OpenResult {
        OpenResult {
            status,
            bound: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.status];
        encode_ip(self.bound.ip(), &mut out);
        out.extend_from_slice(&self.bound.port().to_be_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Result<Option<(OpenResult, usize)>, WireError> {
        let Some(&status) = buf.first() else {
            return Ok(None);
        };
        let Some((host, used)) = parse_host(&buf[1..], false)? else {
            return Ok(None);
        };
        let Host::Ip(ip) = host else {
            unreachable!("domains rejected above")
        };
        if buf.len() < 1 + used + 2 {
            return Ok(None);
        }
        let port = be16(&buf[1 + used..]);
        Ok(Some((
            OpenResult {
                status,
                bound: SocketAddr::new(ip, port),
            },
            1 + used + 2,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn key() -> XorKey {
        XorKey::new(hex("5a a5 3c")).unwrap()
    }

    fn xored(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        key().apply(&mut out);
        out
    }

    const SESSION: u32 = 0x01020304;

    fn ack(stream: u32, next_expected: u32, sack: u32, credit_delta: u16) -> Frame {
        Frame::StreamAck(StreamAck {
            stream,
            next_expected,
            sack,
            credit_delta,
        })
    }

    /// Encode, compare with the A.7 plain/XOR lines, and decode back.
    fn check(env: &Envelope, plain: &str, xor: &str) {
        let encoded = env.encode();
        assert_eq!(encoded, hex(plain));
        assert_eq!(xored(&encoded), hex(xor));
        let dir = if env.rx_lag.is_some() {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        assert_eq!(&Envelope::decode(&xored(&hex(xor)), dir).unwrap(), env);
    }

    #[test]
    fn empty_key_rejected() {
        assert!(XorKey::new(Vec::new()).is_none());
        assert_eq!(format!("{:?}", key()), "XorKey(<3 bytes redacted>)");
    }

    #[test]
    fn v1_poll() {
        check(
            &Envelope::client(SESSION, 5, 1, vec![]),
            "20 01 02 03 04 00 00 00 05 01",
            "7a a4 3e 59 a1 3c 5a a5 39 5b",
        );
    }

    #[test]
    fn v2_ack_and_segment() {
        let env = Envelope::client(
            SESSION,
            6,
            1,
            vec![
                ack(1, 3, 2, 30),
                Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: b"hello".to_vec(),
                },
            ],
        );
        check(
            &env,
            "20 01 02 03 04 00 00 00 06 01 12 0e 00 00 00 01 00 00 00 03 00 00 00 02 00 1e 10 0d 00 00 00 01 00 00 00 00 68 65 6c 6c 6f",
            "7a a4 3e 59 a1 3c 5a a5 3a 5b b7 32 5a a5 3c 5b a5 3c 5a a6 3c 5a a5 3e 5a bb 2c 57 a5 3c 5a a4 3c 5a a5 3c 32 c0 50 36 ca",
        );
    }

    pub(crate) fn v3_cookie() -> [u8; COOKIE_LEN] {
        let secret: [u8; 32] = std::array::from_fn(|i| i as u8);
        let cn: [u8; 16] = std::array::from_fn(|i| i as u8);
        let sn: [u8; 16] = std::array::from_fn(|i| 16 + i as u8);
        let domain = hex("01 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00");
        let input = CookieInput {
            domain_wire: &domain,
            client_nonce: &cn,
            server_nonce: &sn,
            u: 111,
            d: 182,
        };
        input.make(&secret, 1_700_000_030)
    }

    #[test]
    fn v3_handshake() {
        let cookie = v3_cookie();
        assert_eq!(
            cookie.to_vec(),
            hex("65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57")
        );
        let cn: [u8; 16] = std::array::from_fn(|i| i as u8);
        let sn: [u8; 16] = std::array::from_fn(|i| 16 + i as u8);
        check(
            &Envelope::client(0, 1, 255, vec![Frame::Hello { client_nonce: cn }]),
            "20 00 00 00 00 00 00 00 01 ff 01 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f",
            "7a a5 3c 5a a5 3c 5a a5 3d a5 a4 2c 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55",
        );
        check(
            &Envelope::server(
                0,
                1,
                vec![Frame::Challenge {
                    server_nonce: sn,
                    u: 111,
                    d: 182,
                    cookie,
                }],
            ),
            "20 00 00 00 00 00 00 00 01 02 28 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 6f 00 b6 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57",
            "7a a5 3c 5a a5 3c 5a a5 3d 58 8d 2c 4b b7 2f 4e b0 2a 4d bd 25 40 be 20 47 bb 23 5a ca 3c ec c0 6f ab bb ac 2d 17 4b fa 0e eb 9a 46 dd 4f f0 f8 63 94 6b",
        );
        check(
            &Envelope::client(
                0,
                2,
                255,
                vec![Frame::CookieEcho {
                    client_nonce: cn,
                    server_nonce: sn,
                    cookie,
                }],
            ),
            "20 00 00 00 00 00 00 00 02 ff 03 34 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57",
            "7a a5 3c 5a a5 3c 5a a5 3e a5 a6 08 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55 b5 2d 48 b6 28 4f b3 2b 42 bc 26 41 b9 21 44 ba 59 09 54 22 ca d2 8e 2d 05 97 8d 65 df bb b0 69 9e 9c 0d 0d",
        );
        check(
            &Envelope::server(
                0,
                2,
                vec![Frame::Accept {
                    session_id: SESSION,
                }],
            ),
            "20 00 00 00 00 00 00 00 02 04 04 01 02 03 04",
            "7a a5 3c 5a a5 3c 5a a5 3e 5e a1 3d 58 a6 38",
        );
    }

    #[test]
    fn cookie_verification() {
        let secret: [u8; 32] = std::array::from_fn(|i| i as u8);
        let cn: [u8; 16] = std::array::from_fn(|i| i as u8);
        let sn: [u8; 16] = std::array::from_fn(|i| 16 + i as u8);
        let domain = hex("01 74 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00");
        let input = CookieInput {
            domain_wire: &domain,
            client_nonce: &cn,
            server_nonce: &sn,
            u: 111,
            d: 182,
        };
        let cookie = v3_cookie();
        assert!(input.verify(&secret, &cookie, 1_700_000_000));
        assert!(
            !input.verify(&secret, &cookie, 1_700_000_030),
            "exact expiry is expired"
        );
        let mut tampered = cookie;
        tampered[19] ^= 1;
        assert!(!input.verify(&secret, &tampered, 1_700_000_000));
        let mut later = cookie;
        later[3] ^= 1;
        assert!(
            !input.verify(&secret, &later, 1_700_000_000),
            "expiry is MAC-bound"
        );
        let other = CookieInput { u: 112, ..input };
        assert!(!other.verify(&secret, &cookie, 1_700_000_000));
    }

    #[test]
    fn v5_fin_envelopes() {
        check(
            &Envelope::client(SESSION, 7, 1, vec![Frame::Fin { stream: 1, seq: 32 }]),
            "20 01 02 03 04 00 00 00 07 01 11 08 00 00 00 01 00 00 00 20",
            "7a a4 3e 59 a1 3c 5a a5 3b 5b b4 34 5a a5 3c 5b a5 3c 5a 85",
        );
        check(
            &Envelope::server(SESSION, 7, vec![ack(1, 33, 0, 0)]),
            "20 01 02 03 04 00 00 00 07 12 0e 00 00 00 01 00 00 00 21 00 00 00 00 00 00",
            "7a a4 3e 59 a1 3c 5a a5 3b 48 ab 3c 5a a5 3d 5a a5 3c 7b a5 3c 5a a5 3c 5a",
        );
    }

    #[test]
    fn v6_lag_evidence() {
        assert_eq!(response_evidence(1000, 254), Some(746));
        assert_eq!(response_evidence(1000, 255), None);
        assert_eq!(response_evidence(1001, 1), Some(1000));
        check(
            &Envelope::client(SESSION, 1000, 255, vec![ack(1, 3, 2, 30)]),
            "20 01 02 03 04 00 00 03 e8 ff 12 0e 00 00 00 01 00 00 00 03 00 00 00 02 00 1e",
            "7a a4 3e 59 a1 3c 5a a6 d4 a5 b7 32 5a a5 3c 5b a5 3c 5a a6 3c 5a a5 3e 5a bb",
        );
        // Lag zero, and an exact lag reaching the exchange ID, are invalid.
        let mut bad = Envelope::client(SESSION, 1000, 1, vec![]).encode();
        bad[9] = 0;
        assert!(Envelope::decode(&bad, Direction::ClientToServer).is_err());
        let mut bad = Envelope::client(SESSION, 5, 1, vec![]).encode();
        bad[9] = 5;
        assert!(Envelope::decode(&bad, Direction::ClientToServer).is_err());
        bad[9] = 4;
        assert!(Envelope::decode(&bad, Direction::ClientToServer).is_ok());
    }

    #[test]
    fn v7_open_and_reset() {
        let open = Target {
            host: Host::Ip("203.0.113.7".parse().unwrap()),
            port: 443,
        };
        assert_eq!(open.encode(), hex("01 cb 00 71 07 01 bb"));
        check(
            &Envelope::client(
                SESSION,
                11,
                1,
                vec![Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: open.encode(),
                }],
            ),
            "20 01 02 03 04 00 00 00 0b 01 10 0f 00 00 00 01 00 00 00 00 01 cb 00 71 07 01 bb",
            "7a a4 3e 59 a1 3c 5a a5 37 5b b5 33 5a a5 3c 5b a5 3c 5a a5 3d 91 a5 4d 5d a4 87",
        );
        check(
            &Envelope::server(
                SESSION,
                11,
                vec![Frame::Reset {
                    stream: 1,
                    reason: reset::UNKNOWN_STREAM,
                }],
            ),
            "20 01 02 03 04 00 00 00 0b 13 05 00 00 00 01 06",
            "7a a4 3e 59 a1 3c 5a a5 37 49 a0 3c 5a a5 3d 5c",
        );
    }

    #[test]
    fn v8_retry_and_expired() {
        let cn: [u8; 16] = std::array::from_fn(|i| i as u8);
        let sn: [u8; 16] = std::array::from_fn(|i| 16 + i as u8);
        let cookie = v3_cookie();
        check(
            &Envelope::client(
                0,
                3,
                255,
                vec![Frame::CookieEcho {
                    client_nonce: cn,
                    server_nonce: sn,
                    cookie,
                }],
            ),
            "20 00 00 00 00 00 00 00 03 ff 03 34 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 65 53 f1 1e 90 77 b2 77 a0 ab d7 c0 e3 e1 15 55 c4 39 31 57",
            "7a a5 3c 5a a5 3c 5a a5 3f a5 a6 08 5a a4 3e 59 a1 39 5c a2 34 53 af 37 56 a8 32 55 b5 2d 48 b6 28 4f b3 2b 42 bc 26 41 b9 21 44 ba 59 09 54 22 ca d2 8e 2d 05 97 8d 65 df bb b0 69 9e 9c 0d 0d",
        );
        check(
            &Envelope::server(
                0,
                3,
                vec![Frame::Accept {
                    session_id: SESSION,
                }],
            ),
            "20 00 00 00 00 00 00 00 03 04 04 01 02 03 04",
            "7a a5 3c 5a a5 3c 5a a5 3f 5e a1 3d 58 a6 38",
        );
        check(
            &Envelope::server(
                0,
                4,
                vec![Frame::SessionError {
                    reason: session_error::HANDSHAKE_EXPIRED,
                }],
            ),
            "20 00 00 00 00 00 00 00 04 20 01 06",
            "7a a5 3c 5a a5 3c 5a a5 38 7a a4 3a",
        );
    }

    #[test]
    fn v9_credit_repeat() {
        check(
            &Envelope::server(SESSION, 12, vec![ack(1, 32, 0, 8)]),
            "20 01 02 03 04 00 00 00 0c 12 0e 00 00 00 01 00 00 00 20 00 00 00 00 00 08",
            "7a a4 3e 59 a1 3c 5a a5 30 48 ab 3c 5a a5 3d 5a a5 3c 7a a5 3c 5a a5 3c 52",
        );
    }

    #[test]
    fn malformed_envelopes() {
        let c2s = Direction::ClientToServer;
        let s2c = Direction::ServerToClient;
        let poll = Envelope::client(SESSION, 5, 1, vec![]).encode();
        assert!(Envelope::decode(&poll[..9], c2s).is_err());
        let mut v2 = poll.clone();
        v2[0] = 0x40;
        assert_eq!(
            Envelope::decode(&v2, c2s),
            Err(WireError::UnsupportedVersion)
        );
        for flag in [0x01, 0x04, 0x08, 0x10] {
            let mut f = poll.clone();
            f[0] |= flag;
            assert!(
                Envelope::decode(&f, c2s).is_err(),
                "reserved flag {flag:#x}"
            );
        }
        let mut more = poll.clone();
        more[0] |= FLAG_MORE_PENDING;
        assert!(
            Envelope::decode(&more, c2s).is_err(),
            "MORE_PENDING only from server"
        );
        let mut zero_ex = poll.clone();
        zero_ex[8] = 0;
        assert!(Envelope::decode(&zero_ex, c2s).is_err());
        // Frame length past the end, unknown kind, wrong body sizes.
        for tail in [
            "12 0e 00",
            "7f 00",
            "11 07 00 00 00 01 00 00 00",
            "10 08 00 00 00 01 00 00 00 00",
        ] {
            let mut bad = poll.clone();
            bad.extend(hex(tail));
            assert!(Envelope::decode(&bad, c2s).is_err(), "{tail}");
        }
        // Direction checks.
        let mut challenge_from_client = Envelope::client(0, 1, 255, vec![]).encode();
        Frame::Accept { session_id: 1 }.encode(&mut challenge_from_client);
        assert!(Envelope::decode(&challenge_from_client, c2s).is_err());
        // Placement: handshake frames only with session 0, and alone.
        let mut hello_in_session = Envelope::client(SESSION, 1, 255, vec![]).encode();
        Frame::Hello {
            client_nonce: [0; 16],
        }
        .encode(&mut hello_in_session);
        assert!(Envelope::decode(&hello_in_session, c2s).is_err());
        assert!(Envelope::decode(&Envelope::client(0, 1, 255, vec![]).encode(), c2s).is_err());
        let two = Envelope::server(
            SESSION,
            1,
            vec![
                Frame::SessionError { reason: 1 },
                Frame::SessionError { reason: 1 },
            ],
        );
        assert!(Envelope::decode(&two.encode(), s2c).is_err());
        let reserved = Envelope::server(SESSION, 1, vec![Frame::SessionError { reason: 4 }]);
        assert!(Envelope::decode(&reserved.encode(), s2c).is_err());
        // Every truncation of a valid envelope is either a valid prefix or an error, never a panic.
        let full = Envelope::client(
            SESSION,
            6,
            1,
            vec![ack(1, 3, 2, 30), Frame::Fin { stream: 1, seq: 9 }],
        )
        .encode();
        for n in 0..full.len() {
            let _ = Envelope::decode(&full[..n], c2s);
        }
    }

    #[test]
    fn opening_records() {
        let name = Target {
            host: Host::Domain("a".repeat(255)),
            port: 80,
        };
        let encoded = name.encode();
        assert_eq!(encoded.len(), 259, "longest OPEN");
        for n in 0..encoded.len() {
            assert_eq!(Target::parse(&encoded[..n]), Ok(None));
        }
        assert_eq!(Target::parse(&encoded), Ok(Some((name, 259))));
        let v6 = Target {
            host: Host::Ip("2001:db8::1".parse().unwrap()),
            port: 8080,
        };
        let mut buf = v6.encode();
        buf.extend_from_slice(b"extra");
        assert_eq!(Target::parse(&buf), Ok(Some((v6, 19))));
        assert!(Target::parse(&hex("02 00")).is_err());
        assert!(Target::parse(&hex("03 00 00 50")).is_err());
        assert!(Target::parse(b"\x03\x03a b\x00\x50").is_err());

        let ok = OpenResult {
            status: 0,
            bound: "198.51.100.2:4000".parse().unwrap(),
        };
        assert_eq!(OpenResult::parse(&ok.encode()), Ok(Some((ok, 8))));
        let fail = OpenResult::failure(status::CONNECTION_REFUSED);
        assert_eq!(fail.encode(), hex("05 01 00 00 00 00 00 00"));
        assert!(
            OpenResult::parse(&hex("00 03 01 61 00 50")).is_err(),
            "no domain in OPEN_RESULT"
        );
        assert_eq!(OpenResult::parse(&hex("00 04 00")), Ok(None));
    }
}
