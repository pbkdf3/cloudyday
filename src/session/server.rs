//! Authoritative server: handshake, sessions, streams, and the UDP driver.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use super::{
    ACK_BATCH, Budget, Chunk, HasPipe, IoEvent, IoKind, MAX_STREAMS, OPEN_DEADLINE, Packer, Pipe,
    Reservation, ResetRepeats, SESSION_EXPIRY, TokenBucket, Tombstone, Tombstones, WRITE_QUEUE,
    now, pack_acks, pack_data,
};
use crate::arq::{Delivery, Rtt};
use crate::dns::{self, Sizes, TunnelDomain};
use crate::wire::{
    CookieInput, Direction, Envelope, Frame, MAX_OPEN_RECORD, NONCE_LEN, OpenResult,
    SERVER_HEADER_LEN, StreamAck, Target, WireError, XorKey, peek_ids, reset, response_evidence,
    session_error, status,
};
use crate::{filter, socks};

pub const MAX_SESSIONS: usize = 64;
pub const BUFFER_LIMIT: usize = 32 << 20;
const COOKIE_LIFETIME: u64 = 30;
const MAX_HANDSHAKES: usize = 256;
const EXCHANGE_WINDOW: u32 = 1024;
const RESPONSE_CACHE: usize = 256;
const RESPONSE_CACHE_AGE: Duration = Duration::from_secs(5);
const REORDER_ALLOWANCE: u32 = 3;
const STREAM_ID_WINDOW: u32 = 64;
const MAX_ERROR_SOURCES: usize = 4096;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    bytes
}

/// Work for the driver: start one destination connection attempt.
#[derive(Debug)]
pub enum Action {
    Dial {
        key: u64,
        target: Target,
        deadline: Instant,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum IdCheck {
    Fresh,
    TooOld,
    Used,
}

/// High-water mark plus used-ID bitmap (A.5). Bits are never cleared while
/// their IDs remain in the window.
#[derive(Debug, Default)]
struct StreamIds {
    high: u32,
    bits: u64,
}

impl StreamIds {
    fn check(&mut self, id: u32) -> IdCheck {
        let low = self.high.saturating_sub(STREAM_ID_WINDOW - 1).max(1);
        if id < low {
            return IdCheck::TooOld;
        }
        if id <= self.high && self.bits & 1 << (self.high - id) != 0 {
            return IdCheck::Used;
        }
        if id > self.high {
            let shift = id - self.high;
            self.bits = if shift >= STREAM_ID_WINDOW {
                0
            } else {
                self.bits << shift
            };
            self.high = id;
        }
        self.bits |= 1 << (self.high - id);
        IdCheck::Fresh
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    New,
    Duplicate,
    Below,
}

/// The 1024 most recent exchange IDs seen in a session.
#[derive(Debug, Default)]
struct Exchanges {
    high: u32,
    seen: BTreeSet<u32>,
}

impl Exchanges {
    fn check(&mut self, exchange: u32) -> Seen {
        if self.high >= EXCHANGE_WINDOW && exchange <= self.high - EXCHANGE_WINDOW {
            return Seen::Below;
        }
        if !self.seen.insert(exchange) {
            return Seen::Duplicate;
        }
        if exchange > self.high {
            self.high = exchange;
            self.seen = self
                .seen
                .split_off(&exchange.saturating_sub(EXCHANGE_WINDOW - 1));
        }
        Seen::New
    }
}

#[derive(Debug)]
struct CachedResponse {
    exchange: u32,
    at: Instant,
    envelope: Vec<u8>,
    _hold: Reservation,
}

/// Plain response envelopes for recent exchanges, so a duplicate query gets
/// the identical envelope instead of stranding dequeued frames.
#[derive(Debug, Default)]
struct ResponseCache {
    entries: VecDeque<CachedResponse>,
}

impl ResponseCache {
    fn prune(&mut self, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|e| now >= e.at + RESPONSE_CACHE_AGE)
        {
            self.entries.pop_front();
        }
    }

    fn get(&mut self, exchange: u32, now: Instant) -> Option<Vec<u8>> {
        self.prune(now);
        self.entries
            .iter()
            .find(|e| e.exchange == exchange)
            .map(|e| e.envelope.clone())
    }

    fn insert(&mut self, exchange: u32, envelope: Vec<u8>, now: Instant, budget: &Budget) {
        self.prune(now);
        if self.entries.len() >= RESPONSE_CACHE {
            self.entries.pop_front();
        }
        loop {
            if let Some(hold) = budget.try_reserve(envelope.len()) {
                self.entries.push_back(CachedResponse {
                    exchange,
                    at: now,
                    envelope,
                    _hold: hold,
                });
                return;
            }
            if self.entries.pop_front().is_none() {
                return;
            }
        }
    }
}

#[derive(Debug)]
enum Phase {
    /// Collecting the OPEN record.
    Opening {
        buf: Vec<u8>,
        deadline: Instant,
    },
    /// One connection attempt in flight; bytes after the record wait here.
    Dialing {
        early: Vec<u8>,
    },
    Connected,
    /// OPEN_RESULT failure and FIN queued; incoming bytes are discarded.
    Failed,
}

#[derive(Debug)]
struct ServerStream {
    pipe: Pipe,
    key: u64,
    phase: Phase,
}

impl HasPipe for ServerStream {
    fn pipe(&mut self) -> &mut Pipe {
        &mut self.pipe
    }
}

/// State shared by all sessions, split out so sessions can borrow it.
struct Shared {
    budget: Budget,
    sizes: Sizes,
    actions: Vec<Action>,
    /// Bridge key -> (session, stream).
    keys: HashMap<u64, (u32, u32)>,
    next_key: u64,
}

struct Session {
    id: u32,
    last_activity: Instant,
    exchanges: Exchanges,
    cache: ResponseCache,
    streams: BTreeMap<u32, ServerStream>,
    tombstones: Tombstones,
    ids: StreamIds,
    rtt: Rtt,
    highest_received: Option<u32>,
    resets: ResetRepeats,
    cursor: u32,
}

enum Step {
    Continue,
    Abort(u8),
}

impl Session {
    fn new(id: u32, now: Instant) -> Session {
        Session {
            id,
            last_activity: now,
            exchanges: Exchanges::default(),
            cache: ResponseCache::default(),
            streams: BTreeMap::new(),
            tombstones: Tombstones::default(),
            ids: StreamIds::default(),
            rtt: Rtt::default(),
            highest_received: None,
            resets: ResetRepeats::default(),
            cursor: 0,
        }
    }

    /// Process one tunnel query; returns the plain response envelope.
    fn handle(
        &mut self,
        env: Envelope,
        capacity: usize,
        now: Instant,
        sh: &mut Shared,
    ) -> Option<Vec<u8>> {
        match self.exchanges.check(env.exchange_id) {
            Seen::Below => return None,
            Seen::Duplicate => return self.cache.get(env.exchange_id, now),
            Seen::New => {}
        }
        self.last_activity = now;
        let lag = env.rx_lag.expect("client envelope");
        if let Some(highest) = response_evidence(env.exchange_id, lag) {
            self.highest_received = Some(self.highest_received.map_or(highest, |h| h.max(highest)));
        }

        let mut must_ack = BTreeSet::new();
        let mut replies = Vec::new();
        for frame in env.frames {
            match frame {
                Frame::StreamAck(ack) => self.on_ack(&ack, now, sh),
                Frame::Segment {
                    stream,
                    seq,
                    payload,
                } => self.on_stream_frame(
                    stream,
                    seq,
                    Some(&payload),
                    now,
                    sh,
                    &mut must_ack,
                    &mut replies,
                ),
                Frame::Fin { stream, seq } => {
                    self.on_stream_frame(stream, seq, None, now, sh, &mut must_ack, &mut replies)
                }
                Frame::Reset { stream, reason } => self.on_reset(stream, reason, now, sh),
                _ => {}
            }
        }
        self.detect_losses(now);
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.drive(id, now, sh);
        }
        let envelope = self
            .respond(env.exchange_id, capacity, &must_ack, replies, now, sh)
            .encode();
        self.cache
            .insert(env.exchange_id, envelope.clone(), now, &sh.budget);
        Some(envelope)
    }

    fn on_ack(&mut self, ack: &StreamAck, now: Instant, sh: &mut Shared) {
        let Some(stream) = self.streams.get_mut(&ack.stream) else {
            return;
        };
        match stream.pipe.on_ack(ack, now) {
            Ok(outcome) => {
                if let Some(rtt) = outcome.rtt_sample {
                    self.rtt.sample(rtt);
                }
            }
            Err(e) => {
                debug!(
                    session = self.id,
                    stream = ack.stream,
                    ?e,
                    "rejected STREAM_ACK"
                );
                self.abort(ack.stream, reset::PROTOCOL, now, sh);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_stream_frame(
        &mut self,
        stream: u32,
        seq: u32,
        payload: Option<&[u8]>,
        now: Instant,
        sh: &mut Shared,
        must_ack: &mut BTreeSet<u32>,
        replies: &mut Vec<Frame>,
    ) {
        if stream == 0 {
            replies.push(Frame::Reset {
                stream,
                reason: reset::PROTOCOL,
            });
            return;
        }
        if !self.streams.contains_key(&stream) {
            match self.tombstones.get(stream, now) {
                Some(Tombstone::Closed(ack)) => return replies.push(Frame::StreamAck(ack)),
                Some(Tombstone::Reset(reason)) => {
                    return replies.push(Frame::Reset { stream, reason });
                }
                None => {}
            }
            if self.ids.check(stream) != IdCheck::Fresh {
                return replies.push(Frame::Reset {
                    stream,
                    reason: reset::UNKNOWN_STREAM,
                });
            }
            if self.streams.len() >= MAX_STREAMS {
                warn!(session = self.id, "stream limit reached");
                return replies.push(Frame::Reset {
                    stream,
                    reason: reset::RESOURCE,
                });
            }
            let key = sh.next_key;
            sh.next_key += 1;
            sh.keys.insert(key, (self.id, stream));
            let phase = Phase::Opening {
                buf: Vec::new(),
                deadline: now + OPEN_DEADLINE,
            };
            self.streams.insert(
                stream,
                ServerStream {
                    pipe: Pipe::new(now, sh.sizes.u),
                    key,
                    phase,
                },
            );
        }
        let pipe = &mut self.streams.get_mut(&stream).expect("present").pipe;
        let result = match payload {
            Some(payload) => pipe.on_segment(seq, payload, &sh.budget),
            None => pipe.on_fin(seq),
        };
        match result {
            Ok(_) => {
                must_ack.insert(stream);
            }
            Err(e) => {
                debug!(session = self.id, stream, ?e, "stream protocol violation");
                self.abort(stream, reset::PROTOCOL, now, sh);
            }
        }
    }

    fn on_reset(&mut self, stream: u32, reason: u8, now: Instant, sh: &mut Shared) {
        if let Some(st) = self.streams.remove(&stream) {
            debug!(session = self.id, stream, reason, "stream reset by client");
            sh.keys.remove(&st.key);
            self.tombstones
                .insert(stream, Tombstone::Reset(reset::UNKNOWN_STREAM), now);
        }
    }

    fn abort(&mut self, stream: u32, reason: u8, now: Instant, sh: &mut Shared) {
        if let Some(st) = self.streams.remove(&stream) {
            debug!(session = self.id, stream, reason, "resetting stream");
            sh.keys.remove(&st.key);
        }
        self.tombstones
            .insert(stream, Tombstone::Reset(reason), now);
        self.resets.push(stream, reason, now);
    }

    fn close(&mut self, stream: u32, now: Instant, sh: &mut Shared) {
        let Some(st) = self.streams.remove(&stream) else {
            return;
        };
        debug!(session = self.id, stream, "stream closed");
        sh.keys.remove(&st.key);
        if let Ok(ack) = st.pipe.ack(stream) {
            self.tombstones.insert(stream, Tombstone::Closed(ack), now);
        }
    }

    /// Exchange evidence first, then the RTO fallback (§5).
    fn detect_losses(&mut self, now: Instant) {
        let rto = self.rtt.rto();
        let evidence = self
            .highest_received
            .and_then(|h| h.checked_sub(REORDER_ALLOWANCE));
        for stream in self.streams.values_mut() {
            let send = &mut stream.pipe.send;
            if let Some(limit) = evidence {
                for (seq, exchange) in send.carried_up_to(limit) {
                    send.mark_lost(seq, exchange, now, rto);
                }
            }
            send.expire(now, rto);
        }
    }

    /// Move received bytes along the stream's current path.
    fn drive(&mut self, id: u32, now: Instant, sh: &mut Shared) {
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        let mut next_phase = None;
        let step = match &mut st.phase {
            Phase::Opening { buf, deadline } => loop {
                match st.pipe.take_one(now) {
                    None => break Step::Continue,
                    Some(Delivery::Fin) => break Step::Abort(reset::PROTOCOL),
                    Some(Delivery::Data(chunk)) => {
                        buf.extend_from_slice(chunk.as_ref());
                        match Target::parse(buf) {
                            Err(_) => break Step::Abort(reset::PROTOCOL),
                            Ok(None) if buf.len() > MAX_OPEN_RECORD => {
                                break Step::Abort(reset::PROTOCOL);
                            }
                            Ok(None) => {}
                            Ok(Some((target, used))) => {
                                debug!(session = self.id, stream = id, %target, "opening");
                                sh.actions.push(Action::Dial {
                                    key: st.key,
                                    target,
                                    deadline: *deadline,
                                });
                                next_phase = Some(Phase::Dialing {
                                    early: buf[used..].to_vec(),
                                });
                                break Step::Continue;
                            }
                        }
                    }
                }
            },
            Phase::Dialing { .. } => Step::Continue,
            Phase::Connected => {
                st.pipe.deliver_to_writer(now);
                Step::Continue
            }
            Phase::Failed => {
                while st.pipe.take_one(now).is_some() {}
                Step::Continue
            }
        };
        if let Some(phase) = next_phase {
            st.phase = phase;
        }
        match step {
            Step::Abort(reason) => self.abort(id, reason, now, sh),
            Step::Continue if st.pipe.finished() => self.close(id, now, sh),
            Step::Continue => {}
        }
    }

    fn respond(
        &mut self,
        exchange: u32,
        capacity: usize,
        must_ack: &BTreeSet<u32>,
        replies: Vec<Frame>,
        now: Instant,
        sh: &mut Shared,
    ) -> Envelope {
        let mut packer = Packer::new(capacity.saturating_sub(SERVER_HEADER_LEN));
        let mut broken = Vec::new();
        // Mandatory: an ACK for every stream that had SEGMENT or FIN frames.
        for &id in must_ack {
            if let Some(stream) = self.streams.get_mut(&id) {
                match stream.pipe.ack(id) {
                    Ok(ack) => {
                        packer.push(Frame::StreamAck(ack));
                        stream.pipe.ack_dirty = false;
                    }
                    Err(_) => broken.push(id),
                }
            } else if let Some(tombstone) = self.tombstones.get(id, now) {
                packer.push(match tombstone {
                    Tombstone::Closed(ack) => Frame::StreamAck(ack),
                    Tombstone::Reset(reason) => Frame::Reset { stream: id, reason },
                });
            }
        }
        for frame in replies {
            packer.push(frame);
        }
        self.resets.pack(&mut packer, now);
        for stream in self.streams.values_mut() {
            stream.pipe.credit_repeat_due(now);
        }
        broken.extend(pack_acks(&mut self.streams, &mut packer, ACK_BATCH));
        pack_data(
            &mut self.streams,
            &mut self.cursor,
            &mut packer,
            exchange,
            usize::MAX,
            now,
        );
        broken.extend(pack_acks(&mut self.streams, &mut packer, usize::MAX));
        for id in broken {
            self.abort(id, reset::EXHAUSTED, now, sh);
        }
        let more_pending = self.resets.due(now)
            || self
                .streams
                .values()
                .any(|s| s.pipe.send.has_sendable() || s.pipe.ack_dirty);
        let mut envelope = Envelope::server(self.id, exchange, packer.into_frames());
        envelope.more_pending = more_pending;
        envelope
    }

    fn on_io(&mut self, id: u32, kind: IoKind, now: Instant, sh: &mut Shared) {
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        match kind {
            IoKind::Connected {
                writer,
                permits,
                local,
            } => {
                let Phase::Dialing { early } = &mut st.phase else {
                    return;
                };
                let early = mem::take(early);
                st.pipe.permits = Some(permits);
                let record = OpenResult {
                    status: status::SUCCEEDED,
                    bound: local,
                }
                .encode();
                let used = st.pipe.push_record(&record, sh.sizes.d);
                st.pipe.grant_initial_permits(used);
                if !early.is_empty() {
                    // The queue is fresh, so this cannot fail.
                    let _ = writer.try_send(super::WriteCmd::Data(Chunk::new(early)));
                }
                st.pipe.writer = Some(writer);
                st.phase = Phase::Connected;
                debug!(session = self.id, stream = id, "destination connected");
            }
            IoKind::DialFailed(code) => {
                if !matches!(st.phase, Phase::Dialing { .. }) {
                    return;
                }
                debug!(
                    session = self.id,
                    stream = id,
                    status = code,
                    "destination connection failed"
                );
                st.pipe
                    .push_record(&OpenResult::failure(code).encode(), sh.sizes.d);
                st.pipe.push_fin();
                st.phase = Phase::Failed;
            }
            IoKind::Data(chunk) => {
                if !st.pipe.push_data(chunk) {
                    return self.abort(id, reset::EXHAUSTED, now, sh);
                }
            }
            IoKind::Eof => {
                if !st.pipe.push_fin() {
                    return self.abort(id, reset::EXHAUSTED, now, sh);
                }
            }
            IoKind::ReadError | IoKind::WriteError => {
                return self.abort(id, reset::LOCAL_ABORT, now, sh);
            }
            IoKind::Written | IoKind::Open { .. } | IoKind::Closed => {}
        }
        self.drive(id, now, sh);
    }

    fn housekeeping(&mut self, now: Instant, sh: &mut Shared) {
        let mut aborts = Vec::new();
        for (&id, stream) in &self.streams {
            if stream.pipe.stalled(now) {
                aborts.push((id, reset::STALLED));
            } else if let Phase::Opening { deadline, .. } = stream.phase
                && now >= deadline
            {
                aborts.push((id, reset::OPEN_DEADLINE));
            }
        }
        for (id, reason) in aborts {
            self.abort(id, reason, now, sh);
        }
        self.tombstones.prune(now);
        self.cache.prune(now);
    }
}

/// The server's sans-I/O core: DNS datagrams and TCP events in, DNS
/// responses and dial actions out.
pub struct ServerCore {
    domain: TunnelDomain,
    key: XorKey,
    secret: [u8; 32],
    sessions: HashMap<u32, Session>,
    shared: Shared,
    /// COOKIE_ECHO body -> (assigned session, cookie expiry).
    handshakes: HashMap<[u8; 52], (u32, u64)>,
    handshake_rate: TokenBucket,
    error_rate: HashMap<IpAddr, TokenBucket>,
}

impl ServerCore {
    pub fn new(domain: TunnelDomain, key: XorKey, budget: Budget) -> Result<ServerCore, String> {
        let sizes = domain.sizes()?;
        let start = now();
        Ok(ServerCore {
            domain,
            key,
            secret: random_bytes(),
            sessions: HashMap::new(),
            shared: Shared {
                budget,
                sizes,
                actions: Vec::new(),
                keys: HashMap::new(),
                next_key: 1,
            },
            handshakes: HashMap::new(),
            handshake_rate: TokenBucket::new(10.0, 20.0, start),
            error_rate: HashMap::new(),
        })
    }

    pub fn take_actions(&mut self) -> Vec<Action> {
        mem::take(&mut self.shared.actions)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn handle_datagram(
        &mut self,
        src: SocketAddr,
        packet: &[u8],
        now: Instant,
        unix: u64,
    ) -> Option<Vec<u8>> {
        let query = dns::parse_query(packet)?;
        let Some(prefix) = query.zone_prefix(&self.domain) else {
            return Some(query.refused());
        };
        let Some(mut payload) = query.tunnel_payload(prefix) else {
            return Some(query.non_tunnel_answer(prefix));
        };
        self.key.apply(&mut payload);
        let capacity = dns::response_capacity(query.question_len());
        let response = match Envelope::decode(&payload, Direction::ClientToServer) {
            Ok(env) if env.session_id == 0 => self.handshake(&env, now, unix)?.encode(),
            Ok(env) => match self.sessions.get_mut(&env.session_id) {
                Some(session) => session.handle(env, capacity, now, &mut self.shared)?,
                None => self.session_error(
                    src,
                    env.session_id,
                    env.exchange_id,
                    session_error::UNKNOWN_SESSION,
                    now,
                )?,
            },
            Err(WireError::UnsupportedVersion) => {
                let (session, exchange) = peek_ids(&payload)?;
                self.session_error(
                    src,
                    session,
                    exchange,
                    session_error::UNSUPPORTED_VERSION,
                    now,
                )?
            }
            Err(_) => return Some(query.non_tunnel_answer(prefix)),
        };
        let mut xored = response;
        self.key.apply(&mut xored);
        let packet = query.tunnel_response(&xored);
        if packet.is_none() {
            error!("internal error: response exceeds the 512-byte budget");
        }
        packet
    }

    fn session_error(
        &mut self,
        src: SocketAddr,
        session: u32,
        exchange: u32,
        reason: u8,
        now: Instant,
    ) -> Option<Vec<u8>> {
        if !self.error_rate.contains_key(&src.ip()) && self.error_rate.len() >= MAX_ERROR_SOURCES {
            self.error_rate.retain(|_, bucket| !bucket.full(now));
            if self.error_rate.len() >= MAX_ERROR_SOURCES {
                return None;
            }
        }
        let bucket = self
            .error_rate
            .entry(src.ip())
            .or_insert_with(|| TokenBucket::new(10.0, 10.0, now));
        if !bucket.allow(now) {
            return None;
        }
        debug!(session, reason, "SESSION_ERROR");
        Some(Envelope::server(session, exchange, vec![Frame::SessionError { reason }]).encode())
    }

    fn handshake(&mut self, env: &Envelope, now: Instant, unix: u64) -> Option<Envelope> {
        if !self.handshake_rate.allow(now) {
            debug!("handshake rate limit");
            return None;
        }
        let busy = Frame::SessionError {
            reason: session_error::BUSY,
        };
        let sizes = self.shared.sizes;
        let frame = match &env.frames[0] {
            Frame::Hello { client_nonce } => {
                if self.sessions.len() >= MAX_SESSIONS {
                    warn!("session table full; refusing handshake");
                    busy
                } else {
                    let server_nonce: [u8; NONCE_LEN] = random_bytes();
                    let expiry = u32::try_from(unix + COOKIE_LIFETIME).unwrap_or(u32::MAX);
                    let cookie = self
                        .cookie_input(client_nonce, &server_nonce)
                        .make(&self.secret, expiry);
                    Frame::Challenge {
                        server_nonce,
                        u: sizes.u as u16,
                        d: sizes.d as u16,
                        cookie,
                    }
                }
            }
            Frame::CookieEcho {
                client_nonce,
                server_nonce,
                cookie,
            } => {
                if !self
                    .cookie_input(client_nonce, server_nonce)
                    .verify(&self.secret, cookie, unix)
                {
                    Frame::SessionError {
                        reason: session_error::HANDSHAKE_EXPIRED,
                    }
                } else {
                    self.handshakes.retain(|_, &mut (_, expiry)| expiry > unix);
                    let mut body = [0u8; 52];
                    body[..16].copy_from_slice(client_nonce);
                    body[16..32].copy_from_slice(server_nonce);
                    body[32..].copy_from_slice(cookie);
                    if let Some(&(session_id, _)) = self.handshakes.get(&body) {
                        Frame::Accept { session_id }
                    } else if self.handshakes.len() >= MAX_HANDSHAKES
                        || self.sessions.len() >= MAX_SESSIONS
                    {
                        warn!("handshake or session table full; refusing handshake");
                        busy
                    } else {
                        let session_id = self.fresh_session_id();
                        let expiry =
                            u64::from(u32::from_be_bytes(cookie[..4].try_into().expect("4 bytes")));
                        self.handshakes.insert(body, (session_id, expiry));
                        self.sessions
                            .insert(session_id, Session::new(session_id, now));
                        info!(session = format!("{session_id:08x}"), "session established");
                        Frame::Accept { session_id }
                    }
                }
            }
            _ => return None,
        };
        Some(Envelope::server(0, env.exchange_id, vec![frame]))
    }

    fn cookie_input<'a>(
        &'a self,
        client_nonce: &'a [u8; 16],
        server_nonce: &'a [u8; 16],
    ) -> CookieInput<'a> {
        let sizes = self.shared.sizes;
        CookieInput {
            domain_wire: self.domain.wire(),
            client_nonce,
            server_nonce,
            u: sizes.u as u16,
            d: sizes.d as u16,
        }
    }

    fn fresh_session_id(&self) -> u32 {
        loop {
            let id = u32::from_be_bytes(random_bytes());
            if id != 0 && !self.sessions.contains_key(&id) {
                return id;
            }
        }
    }

    pub fn handle_io(&mut self, event: IoEvent, now: Instant) {
        let Some(&(session_id, stream)) = self.shared.keys.get(&event.key) else {
            return;
        };
        match self.sessions.get_mut(&session_id) {
            Some(session) => session.on_io(stream, event.kind, now, &mut self.shared),
            None => {
                self.shared.keys.remove(&event.key);
            }
        }
    }

    pub fn housekeeping(&mut self, now: Instant, unix: u64) {
        let shared = &mut self.shared;
        self.sessions.retain(|&id, session| {
            if now < session.last_activity + SESSION_EXPIRY {
                return true;
            }
            info!(
                session = format!("{id:08x}"),
                streams = session.streams.len(),
                "session expired"
            );
            for stream in session.streams.values() {
                shared.keys.remove(&stream.key);
            }
            false
        });
        for session in self.sessions.values_mut() {
            session.housekeeping(now, shared);
        }
        self.handshakes.retain(|_, &mut (_, expiry)| expiry > unix);
        self.error_rate.retain(|_, bucket| !bucket.full(now));
    }

    #[cfg(test)]
    fn with_secret(mut self, secret: [u8; 32]) -> ServerCore {
        self.secret = secret;
        self
    }
}

pub struct ServerOptions {
    pub domain: TunnelDomain,
    pub key: XorKey,
    pub allow_private: bool,
}

/// The UDP DNS server and its destination bridges.
pub struct Server {
    socket: UdpSocket,
    core: ServerCore,
    budget: Budget,
    allow_private: bool,
}

impl Server {
    pub async fn bind(listen: SocketAddr, options: ServerOptions) -> io::Result<Server> {
        let budget = Budget::new(BUFFER_LIMIT);
        let core = ServerCore::new(options.domain, options.key, budget.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let socket = UdpSocket::bind(listen).await?;
        Ok(Server {
            socket,
            core,
            budget,
            allow_private: options.allow_private,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn run(mut self) -> io::Result<()> {
        let (events_tx, mut events) = mpsc::channel(1024);
        let mut buf = vec![0u8; 65535];
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let segment = self.core.shared.sizes.d;
        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => match received {
                    Ok((n, src)) => {
                        if let Some(response) = self.core.handle_datagram(src, &buf[..n], now(), unix_now())
                            && let Err(e) = self.socket.send_to(&response, src).await {
                                debug!(%src, %e, "send failed");
                            }
                    }
                    Err(e) => debug!(%e, "receive failed"),
                },
                Some(event) = events.recv() => self.core.handle_io(event, now()),
                _ = tick.tick() => self.core.housekeeping(now(), unix_now()),
            }
            for action in self.core.take_actions() {
                let Action::Dial {
                    key,
                    target,
                    deadline,
                } = action;
                let events = events_tx.clone();
                let budget = self.budget.clone();
                let allow_private = self.allow_private;
                tokio::spawn(async move {
                    let deadline = tokio::time::Instant::from_std(deadline);
                    let kind = match filter::dial(&target, deadline, allow_private).await {
                        Ok(tcp) => {
                            let local = tcp
                                .local_addr()
                                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                            let (writer, writes) = mpsc::channel(WRITE_QUEUE);
                            let permits = Arc::new(Semaphore::new(0));
                            let connected = IoKind::Connected {
                                writer,
                                permits: permits.clone(),
                                local,
                            };
                            if events
                                .send(IoEvent {
                                    key,
                                    kind: connected,
                                })
                                .await
                                .is_ok()
                            {
                                socks::bridge(tcp, key, segment, events, permits, writes, budget)
                                    .await;
                            }
                            return;
                        }
                        Err(code) => IoKind::DialFailed(code),
                    };
                    let _ = events.send(IoEvent { key, kind }).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::build_query;
    use crate::wire::{Host, LAG_UNKNOWN};

    const UNIX: u64 = 1_700_000_000;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    struct Harness {
        core: ServerCore,
        key: XorKey,
        domain: TunnelDomain,
        t0: Instant,
        src: SocketAddr,
    }

    impl Harness {
        fn new() -> Harness {
            let domain = TunnelDomain::parse("t.example.com").unwrap();
            let key = XorKey::new(hex("5a a5 3c")).unwrap();
            let core = ServerCore::new(domain.clone(), key.clone(), Budget::new(BUFFER_LIMIT))
                .unwrap()
                .with_secret(std::array::from_fn(|i| i as u8));
            Harness {
                core,
                key,
                domain,
                t0: Instant::now(),
                src: "192.0.2.1:5353".parse().unwrap(),
            }
        }

        fn exchange_at(&mut self, env: &Envelope, at: Duration, unix: u64) -> Option<Envelope> {
            let mut bytes = env.encode();
            self.key.apply(&mut bytes);
            let query = build_query(0x4242, &bytes, &self.domain).unwrap();
            let packet = self
                .core
                .handle_datagram(self.src, &query.packet, self.t0 + at, unix)?;
            let mut payload = dns::parse_response(&packet, &query.qname).unwrap();
            self.key.apply(&mut payload);
            Some(Envelope::decode(&payload, Direction::ServerToClient).unwrap())
        }

        fn exchange(&mut self, env: &Envelope) -> Option<Envelope> {
            self.exchange_at(env, Duration::ZERO, UNIX)
        }

        fn establish(&mut self) -> u32 {
            let cn = [7; 16];
            let challenge = self
                .exchange(&Envelope::client(
                    0,
                    1,
                    LAG_UNKNOWN,
                    vec![Frame::Hello { client_nonce: cn }],
                ))
                .unwrap();
            let Frame::Challenge {
                server_nonce,
                u,
                d,
                cookie,
            } = challenge.frames[0]
            else {
                panic!()
            };
            assert_eq!((u, d), (111, 182));
            let echo = Frame::CookieEcho {
                client_nonce: cn,
                server_nonce,
                cookie,
            };
            let accept = self
                .exchange(&Envelope::client(0, 2, LAG_UNKNOWN, vec![echo]))
                .unwrap();
            let Frame::Accept { session_id } = accept.frames[0] else {
                panic!("{accept:?}")
            };
            session_id
        }
    }

    fn open_frame(stream: u32) -> Frame {
        let target = Target {
            host: Host::Ip("203.0.113.7".parse().unwrap()),
            port: 443,
        };
        Frame::Segment {
            stream,
            seq: 0,
            payload: target.encode(),
        }
    }

    fn dials(core: &mut ServerCore) -> usize {
        core.take_actions().len()
    }

    #[test]
    fn stream_id_window_v7() {
        let mut ids = StreamIds::default();
        assert_eq!(ids.check(1), IdCheck::Fresh);
        assert_eq!(ids.check(1), IdCheck::Used);
        assert_eq!(ids.check(65), IdCheck::Fresh);
        assert_eq!(ids.check(1), IdCheck::TooOld);
        assert_eq!(ids.check(2), IdCheck::Fresh);
        assert_eq!(ids.check(129), IdCheck::Fresh);
        assert_eq!(ids.check(64), IdCheck::TooOld);
        let mut shifted = StreamIds::default();
        shifted.check(1);
        shifted.check(2);
        assert_eq!(
            shifted.check(1),
            IdCheck::Used,
            "sub-window shifts keep bits"
        );
        assert_eq!(shifted.check(u32::MAX), IdCheck::Fresh);
        assert_eq!(shifted.bits, 1);
    }

    #[test]
    fn exchange_window() {
        let mut ex = Exchanges::default();
        assert_eq!(ex.check(5), Seen::New);
        assert_eq!(ex.check(3), Seen::New);
        assert_eq!(ex.check(5), Seen::Duplicate);
        assert_eq!(ex.check(1028), Seen::New);
        assert_eq!(ex.check(4), Seen::Below);
        assert_eq!(ex.check(5), Seen::Duplicate);
        assert_eq!(ex.check(6), Seen::New);
    }

    #[test]
    fn v8_lost_accept_and_cookie_checks() {
        let mut h = Harness::new();
        let cn: [u8; 16] = std::array::from_fn(|i| i as u8);
        let challenge = h
            .exchange(&Envelope::client(
                0,
                1,
                LAG_UNKNOWN,
                vec![Frame::Hello { client_nonce: cn }],
            ))
            .unwrap();
        let Frame::Challenge {
            server_nonce,
            cookie,
            ..
        } = challenge.frames[0]
        else {
            panic!()
        };
        let echo = Frame::CookieEcho {
            client_nonce: cn,
            server_nonce,
            cookie,
        };
        let first = h
            .exchange(&Envelope::client(0, 2, LAG_UNKNOWN, vec![echo.clone()]))
            .unwrap();
        // ACCEPT dropped: the retry gets the same session in a fresh envelope.
        let retry = h
            .exchange_at(
                &Envelope::client(0, 3, LAG_UNKNOWN, vec![echo.clone()]),
                Duration::ZERO,
                UNIX + 2,
            )
            .unwrap();
        assert_eq!(retry.frames, first.frames);
        assert_eq!((retry.exchange_id, retry.session_id), (3, 0));
        assert_eq!(h.core.session_count(), 1);
        // Tampered cookie with cached nonces, and exact expiry.
        let mut bad = cookie;
        bad[19] ^= 1;
        let tampered = Frame::CookieEcho {
            client_nonce: cn,
            server_nonce,
            cookie: bad,
        };
        let expired = vec![Frame::SessionError {
            reason: session_error::HANDSHAKE_EXPIRED,
        }];
        assert_eq!(
            h.exchange(&Envelope::client(0, 4, LAG_UNKNOWN, vec![tampered]))
                .unwrap()
                .frames,
            expired
        );
        let at_expiry = h
            .exchange_at(
                &Envelope::client(0, 4, LAG_UNKNOWN, vec![echo]),
                Duration::ZERO,
                UNIX + 30,
            )
            .unwrap();
        assert_eq!(at_expiry.frames, expired);
        assert_eq!(h.core.session_count(), 1);
    }

    #[test]
    fn full_handshake_cache_refuses_without_eviction() {
        let mut h = Harness::new();
        let mut echoes = Vec::new();
        for i in 0..2u8 {
            let challenge = h
                .exchange(&Envelope::client(
                    0,
                    1,
                    LAG_UNKNOWN,
                    vec![Frame::Hello {
                        client_nonce: [i; 16],
                    }],
                ))
                .unwrap();
            let Frame::Challenge {
                server_nonce,
                cookie,
                ..
            } = challenge.frames[0]
            else {
                panic!()
            };
            echoes.push(Frame::CookieEcho {
                client_nonce: [i; 16],
                server_nonce,
                cookie,
            });
        }
        let first = h
            .exchange(&Envelope::client(
                0,
                2,
                LAG_UNKNOWN,
                vec![echoes[0].clone()],
            ))
            .unwrap();
        // Fill the cache with entries that would expire later.
        for n in 0..MAX_HANDSHAKES - 1 {
            h.core
                .handshakes
                .insert([n as u8; 52], (n as u32 + 100, UNIX + 30));
        }
        let refused = h
            .exchange(&Envelope::client(
                0,
                3,
                LAG_UNKNOWN,
                vec![echoes[1].clone()],
            ))
            .unwrap();
        assert_eq!(
            refused.frames,
            vec![Frame::SessionError {
                reason: session_error::BUSY
            }]
        );
        let retry = h
            .exchange(&Envelope::client(
                0,
                4,
                LAG_UNKNOWN,
                vec![echoes[0].clone()],
            ))
            .unwrap();
        assert_eq!(retry.frames, first.frames, "live entry still answers");
    }

    #[test]
    fn unknown_session_and_version_errors_are_xored() {
        let mut h = Harness::new();
        let reply = h.exchange(&Envelope::client(0xdead, 9, 1, vec![])).unwrap();
        assert_eq!(
            reply.frames,
            vec![Frame::SessionError {
                reason: session_error::UNKNOWN_SESSION
            }]
        );
        assert_eq!((reply.session_id, reply.exchange_id), (0xdead, 9));
        // Version 2 header: SESSION_ERROR(unsupported version).
        let mut bytes = Envelope::client(0xdead, 9, 1, vec![]).encode();
        bytes[0] = 0x40;
        h.key.apply(&mut bytes);
        let query = build_query(1, &bytes, &h.domain).unwrap();
        let packet = h
            .core
            .handle_datagram(h.src, &query.packet, h.t0, UNIX)
            .unwrap();
        let mut payload = dns::parse_response(&packet, &query.qname).unwrap();
        h.key.apply(&mut payload);
        let env = Envelope::decode(&payload, Direction::ServerToClient).unwrap();
        assert_eq!(
            env.frames,
            vec![Frame::SessionError {
                reason: session_error::UNSUPPORTED_VERSION
            }]
        );
        // Unknown-session replies are rate limited per resolver address.
        let answered = (10..40)
            .filter(|&ex| {
                h.exchange(&Envelope::client(0xdead, ex, 1, vec![]))
                    .is_some()
            })
            .count();
        assert!(answered < 30);
    }

    #[test]
    fn duplicate_queries_get_identical_envelopes() {
        let mut h = Harness::new();
        let sid = h.establish();
        let open = Envelope::client(sid, 1, LAG_UNKNOWN, vec![open_frame(1)]);
        let first = h.exchange(&open).unwrap();
        assert_eq!(dials(&mut h.core), 1);
        let again = h.exchange(&open).unwrap();
        assert_eq!(again, first);
        assert_eq!(dials(&mut h.core), 0, "duplicates never dial again");
        // The OPEN record was consumed, so credit already reaches 33.
        let ack = Frame::StreamAck(StreamAck {
            stream: 1,
            next_expected: 1,
            sack: 0,
            credit_delta: 32,
        });
        assert_eq!(first.frames, vec![ack]);
    }

    #[test]
    fn v7_tombstones_never_reopen() {
        let mut h = Harness::new();
        let sid = h.establish();
        h.exchange(&Envelope::client(sid, 1, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        assert_eq!(dials(&mut h.core), 1);
        // Reset by the client: a tombstone answers, then the used bit does.
        h.exchange(&Envelope::client(
            sid,
            2,
            LAG_UNKNOWN,
            vec![Frame::Reset {
                stream: 1,
                reason: 1,
            }],
        ))
        .unwrap();
        let reset_unknown = Frame::Reset {
            stream: 1,
            reason: reset::UNKNOWN_STREAM,
        };
        let reply = h
            .exchange(&Envelope::client(sid, 3, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        assert!(reply.frames.contains(&reset_unknown));
        h.core.sessions.get_mut(&sid).unwrap().tombstones.clear();
        let reply = h
            .exchange(&Envelope::client(sid, 11, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        assert!(reply.frames.contains(&reset_unknown));
        assert_eq!(dials(&mut h.core), 0);
        // Advance the window past 1; it is now too old.
        h.exchange(&Envelope::client(
            sid,
            12,
            LAG_UNKNOWN,
            vec![open_frame(65)],
        ))
        .unwrap();
        assert_eq!(dials(&mut h.core), 1);
        let reply = h
            .exchange(&Envelope::client(sid, 13, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        assert!(reply.frames.contains(&reset_unknown));
        // An unseen in-window ID opens; active streams survive leaving the window.
        h.exchange(&Envelope::client(sid, 14, LAG_UNKNOWN, vec![open_frame(2)]))
            .unwrap();
        assert_eq!(dials(&mut h.core), 1);
        h.exchange(&Envelope::client(
            sid,
            15,
            LAG_UNKNOWN,
            vec![open_frame(129)],
        ))
        .unwrap();
        assert_eq!(dials(&mut h.core), 1);
        let ack2 = Frame::StreamAck(StreamAck {
            stream: 2,
            next_expected: 1,
            sack: 0,
            credit_delta: 32,
        });
        let reply = h
            .exchange(&Envelope::client(sid, 16, LAG_UNKNOWN, vec![open_frame(2)]))
            .unwrap();
        assert_eq!(
            reply.frames,
            vec![ack2],
            "duplicate on active stream 2 is re-ACKed"
        );
        assert_eq!(dials(&mut h.core), 0);
        // Stream zero is a protocol violation.
        let reply = h
            .exchange(&Envelope::client(sid, 17, LAG_UNKNOWN, vec![open_frame(0)]))
            .unwrap();
        assert!(reply.frames.contains(&Frame::Reset {
            stream: 0,
            reason: reset::PROTOCOL
        }));
    }

    #[test]
    fn resource_limit_keeps_used_bit() {
        let mut h = Harness::new();
        let sid = h.establish();
        for id in 1..=MAX_STREAMS as u32 {
            h.exchange(&Envelope::client(
                sid,
                id,
                LAG_UNKNOWN,
                vec![open_frame(id)],
            ))
            .unwrap();
        }
        let over = MAX_STREAMS as u32 + 1;
        let reply = h
            .exchange(&Envelope::client(
                sid,
                100,
                LAG_UNKNOWN,
                vec![open_frame(over)],
            ))
            .unwrap();
        assert!(reply.frames.contains(&Frame::Reset {
            stream: over,
            reason: reset::RESOURCE
        }));
        // Free a slot; the refused ID still never opens.
        h.exchange(&Envelope::client(
            sid,
            101,
            LAG_UNKNOWN,
            vec![Frame::Reset {
                stream: 1,
                reason: 1,
            }],
        ))
        .unwrap();
        let reply = h
            .exchange(&Envelope::client(
                sid,
                102,
                LAG_UNKNOWN,
                vec![open_frame(over)],
            ))
            .unwrap();
        assert!(reply.frames.contains(&Frame::Reset {
            stream: over,
            reason: reset::UNKNOWN_STREAM
        }));
    }

    /// Drive an opened stream to Connected with a fake bridge.
    fn connect(
        h: &mut Harness,
        sid: u32,
        stream: u32,
    ) -> (mpsc::Receiver<super::super::WriteCmd>, Arc<Semaphore>) {
        let actions = h.core.take_actions();
        let Action::Dial { key, .. } = &actions[0];
        let (writer, writes) = mpsc::channel(WRITE_QUEUE);
        let permits = Arc::new(Semaphore::new(0));
        let local = "198.51.100.9:40000".parse().unwrap();
        h.core.handle_io(
            IoEvent {
                key: *key,
                kind: IoKind::Connected {
                    writer,
                    permits: permits.clone(),
                    local,
                },
            },
            h.t0,
        );
        assert!(h.core.sessions[&sid].streams.contains_key(&stream));
        (writes, permits)
    }

    #[test]
    fn open_result_and_lag_based_loss() {
        let mut h = Harness::new();
        let sid = h.establish();
        h.exchange(&Envelope::client(sid, 1, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        let (_writes, permits) = connect(&mut h, sid, 1);
        assert_eq!(permits.available_permits(), 31);
        let reply = h.exchange(&Envelope::client(sid, 2, 1, vec![])).unwrap();
        let result = OpenResult {
            status: 0,
            bound: "198.51.100.9:40000".parse().unwrap(),
        }
        .encode();
        assert_eq!(
            reply.frames,
            vec![Frame::Segment {
                stream: 1,
                seq: 0,
                payload: result.clone()
            }]
        );
        // Responses 3 and 4 are empty; a query proving receipt of response 5
        // without acknowledging seq 0 makes it eligible again.
        h.exchange(&Envelope::client(sid, 3, 1, vec![])).unwrap();
        h.exchange(&Envelope::client(sid, 4, 1, vec![])).unwrap();
        let reply = h.exchange(&Envelope::client(sid, 5, 1, vec![])).unwrap();
        assert!(
            reply.frames.is_empty(),
            "highest received is 4: not yet 3 later than 2"
        );
        let reply = h.exchange(&Envelope::client(sid, 6, 1, vec![])).unwrap();
        assert_eq!(
            reply.frames,
            vec![Frame::Segment {
                stream: 1,
                seq: 0,
                payload: result
            }]
        );
        // Saturated lag never infers receipt; ACKs still apply.
        let ack = Frame::StreamAck(StreamAck {
            stream: 1,
            next_expected: 1,
            sack: 0,
            credit_delta: 32,
        });
        let reply = h
            .exchange(&Envelope::client(sid, 300, LAG_UNKNOWN, vec![ack]))
            .unwrap();
        assert!(reply.frames.is_empty());
        assert_eq!(permits.available_permits(), 32);
    }

    #[test]
    fn dial_failure_finishes_stream() {
        let mut h = Harness::new();
        let sid = h.establish();
        h.exchange(&Envelope::client(sid, 1, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        let actions = h.core.take_actions();
        let Action::Dial { key, .. } = &actions[0];
        h.core.handle_io(
            IoEvent {
                key: *key,
                kind: IoKind::DialFailed(status::NOT_ALLOWED),
            },
            h.t0,
        );
        let reply = h.exchange(&Envelope::client(sid, 2, 1, vec![])).unwrap();
        assert_eq!(
            reply.frames,
            vec![
                Frame::Segment {
                    stream: 1,
                    seq: 0,
                    payload: OpenResult::failure(status::NOT_ALLOWED).encode()
                },
                Frame::Fin { stream: 1, seq: 1 },
            ]
        );
        // Client acknowledges and finishes; the stream closes into a tombstone.
        let ack = Frame::StreamAck(StreamAck {
            stream: 1,
            next_expected: 2,
            sack: 0,
            credit_delta: 32,
        });
        let reply = h
            .exchange(&Envelope::client(
                sid,
                3,
                1,
                vec![ack, Frame::Fin { stream: 1, seq: 1 }],
            ))
            .unwrap();
        let final_ack = StreamAck {
            stream: 1,
            next_expected: 2,
            sack: 0,
            credit_delta: 32,
        };
        assert_eq!(reply.frames, vec![Frame::StreamAck(final_ack)]);
        assert!(h.core.sessions[&sid].streams.is_empty());
        // A late FIN retransmission is re-ACKed from the tombstone.
        let reply = h
            .exchange(&Envelope::client(
                sid,
                4,
                1,
                vec![Frame::Fin { stream: 1, seq: 1 }],
            ))
            .unwrap();
        assert_eq!(reply.frames, vec![Frame::StreamAck(final_ack)]);
    }

    #[test]
    fn data_flow_credit_and_half_close() {
        let mut h = Harness::new();
        let sid = h.establish();
        h.exchange(&Envelope::client(sid, 1, LAG_UNKNOWN, vec![open_frame(1)]))
            .unwrap();
        let (mut writes, _permits) = connect(&mut h, sid, 1);
        // Upload data reaches the writer in order, then FIN becomes Shutdown.
        let seg = |seq: u32, b: u8| Frame::Segment {
            stream: 1,
            seq,
            payload: vec![b; 10],
        };
        h.exchange(&Envelope::client(
            sid,
            2,
            LAG_UNKNOWN,
            vec![seg(2, b'b'), Frame::Fin { stream: 1, seq: 3 }],
        ))
        .unwrap();
        assert!(writes.try_recv().is_err(), "gap at 1");
        h.exchange(&Envelope::client(sid, 3, LAG_UNKNOWN, vec![seg(1, b'a')]))
            .unwrap();
        let mut got = Vec::new();
        while let Ok(cmd) = writes.try_recv() {
            got.push(match cmd {
                super::super::WriteCmd::Data(chunk) => chunk.as_ref()[0],
                super::super::WriteCmd::Shutdown => b'$',
                super::super::WriteCmd::Reply(_) => b'?',
            });
        }
        assert_eq!(got, b"ab$");
        // Download: the destination's bytes go out in round-robin responses.
        let key = h.core.sessions[&sid].streams[&1].key;
        for b in *b"xyz" {
            h.core.handle_io(
                IoEvent {
                    key,
                    kind: IoKind::Data(Chunk::new(vec![b; 182])),
                },
                h.t0,
            );
        }
        h.core.handle_io(
            IoEvent {
                key,
                kind: IoKind::Eof,
            },
            h.t0,
        );
        let reply = h.exchange(&Envelope::client(sid, 4, 1, vec![])).unwrap();
        assert!(reply.more_pending);
        let kinds: Vec<u32> = reply
            .frames
            .iter()
            .filter_map(|f| match f {
                Frame::Segment { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect();
        // OPEN_RESULT (seq 0) went out in an earlier response.
        assert_eq!(kinds, vec![1, 2]);
        let reply = h.exchange(&Envelope::client(sid, 5, 1, vec![])).unwrap();
        assert!(
            reply
                .frames
                .iter()
                .any(|f| matches!(f, Frame::Segment { seq: 3, .. }))
        );
        assert!(reply.frames.contains(&Frame::Fin { stream: 1, seq: 4 }));
        assert!(!reply.more_pending);
        let ack = Frame::StreamAck(StreamAck {
            stream: 1,
            next_expected: 5,
            sack: 0,
            credit_delta: 32,
        });
        h.exchange(&Envelope::client(sid, 6, 1, vec![ack])).unwrap();
        assert!(
            h.core.sessions[&sid].streams.is_empty(),
            "both directions finished"
        );
    }

    #[test]
    fn non_tunnel_queries() {
        let mut h = Harness::new();
        let mut packet = vec![0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&[4, b'x', b'y', b'z', b'w', 1, b't', 7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let answer = h.core.handle_datagram(h.src, &packet, h.t0, UNIX).unwrap();
        assert_eq!(
            &answer[2..4],
            &[0x85, 0x00],
            "NODATA, authoritative, never NXDOMAIN"
        );
        assert_eq!(&answer[6..10], &[0, 0, 0, 1]);
        packet[18] = b'u';
        packet[23] = b'q';
        let refused = h.core.handle_datagram(h.src, &packet, h.t0, UNIX).unwrap();
        assert_eq!(refused[3] & 0x0f, 5);
    }

    #[test]
    fn session_expiry() {
        let mut h = Harness::new();
        let sid = h.establish();
        h.core.housekeeping(h.t0 + Duration::from_secs(59), UNIX);
        assert_eq!(h.core.session_count(), 1);
        h.core.housekeeping(h.t0 + Duration::from_secs(60), UNIX);
        assert_eq!(h.core.session_count(), 0);
        let reply = h
            .exchange_at(
                &Envelope::client(sid, 3, 1, vec![]),
                Duration::from_secs(61),
                UNIX,
            )
            .unwrap();
        assert_eq!(
            reply.frames,
            vec![Frame::SessionError {
                reason: session_error::UNKNOWN_SESSION
            }]
        );
    }
}
