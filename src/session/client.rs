//! Client: handshake, stream opening, query pipeline, and polling.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use super::reverse::{self, Streams};
use super::server::{Action, BUFFER_LIMIT, random_bytes};
use super::{
    ACK_BATCH, Budget, Chunk, HasPipe, IoEvent, IoKind, KEEPALIVE, MAX_STREAMS, OPEN_DEADLINE,
    Packer, Pipe, ResetRepeats, SESSION_EXPIRY, Tombstone, Tombstones, WriteCmd, now, pack_acks,
    pack_data,
};
use crate::arq::{Admit, Delivery, Rtt};
use crate::crypto::{SessionKeys, SharedSecret};
use crate::dns::{self, ResponseError, Sizes, TunnelDomain};
use crate::socks;
use crate::wire::{
    CLIENT_HEADER_LEN, CookieInput, Direction, Envelope, FLAG_PLAIN_ERROR, Frame, LAG_UNKNOWN,
    MAX_OPEN_RECORD, NONCE_LEN, OpenResult, StreamAck, Target, reset, session_error, status,
};

const MIN_DEPTH: usize = 2;
const START_DEPTH: usize = 4;
const MAX_DEPTH: usize = 32;
const LOSS_REORDER: u32 = 3;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TOTAL: Duration = Duration::from_secs(30);
const HANDSHAKE_BACKOFF: Duration = Duration::from_secs(5);
const MAX_PENDING_OPENS: usize = 256;
const DEFAULT_PACE_RTT: Duration = Duration::from_millis(100);
/// Idle time after which pipeline depth decays back toward its start.
const DEPTH_DECAY_IDLE: Duration = Duration::from_secs(1);
/// Upper bound on driver sleeps, for coarse timers.
const MAX_SLEEP: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Hello,
    Echo,
    Session,
}

#[derive(Debug)]
struct Outstanding {
    qname: String,
    exchange: u32,
    sent_at: Instant,
    deadline: Instant,
    generation: u64,
    kind: Kind,
    /// `(stream, seq)` of each SEGMENT or FIN carried.
    carried: Vec<(u32, u32)>,
}

/// DNS-facing state: encodes envelopes into queries and tracks them.
struct Transport {
    domain: TunnelDomain,
    key: SharedSecret,
    crypto: Option<SessionKeys>,
    outstanding: HashMap<u16, Outstanding>,
    out: Vec<Vec<u8>>,
    /// Bumped whenever a handshake starts or a session ends, so responses
    /// to older queries are ignored.
    generation: u64,
}

impl Transport {
    fn send(
        &mut self,
        env: &Envelope,
        kind: Kind,
        deadline: Instant,
        carried: Vec<(u32, u32)>,
        now: Instant,
    ) {
        let mut bytes = env.encode();
        if kind == Kind::Session {
            self.crypto
                .as_ref()
                .expect("established session keys")
                .apply(&mut bytes, Direction::ClientToServer)
                .expect("session envelope");
        }
        let id = loop {
            let id = u16::from_be_bytes(random_bytes());
            if !self.outstanding.contains_key(&id) {
                break id;
            }
        };
        let query = dns::build_query(id, &bytes, &self.domain).expect("envelopes are sized to fit");
        self.out.push(query.packet);
        let generation = self.generation;
        let exchange = env.exchange_id;
        self.outstanding.insert(
            id,
            Outstanding {
                qname: query.qname,
                exchange,
                sent_at: now,
                deadline,
                generation,
                kind,
                carried,
            },
        );
    }

    fn in_flight(&self) -> usize {
        self.outstanding
            .values()
            .filter(|o| o.kind == Kind::Session && o.generation == self.generation)
            .count()
    }
}

#[derive(Debug)]
struct PendingOpen {
    key: u64,
    target: Target,
    writer: mpsc::Sender<WriteCmd>,
    permits: Arc<Semaphore>,
    deadline: Instant,
}

impl PendingOpen {
    fn fail(self, code: u8) {
        let _ = self
            .writer
            .try_send(WriteCmd::Reply(OpenResult::failure(code)));
    }
}

#[derive(Debug)]
enum Stage {
    Hello,
    Echo {
        server_nonce: [u8; NONCE_LEN],
        cookie: [u8; 20],
    },
}

#[derive(Debug)]
struct Handshake {
    started: Instant,
    nonce: [u8; NONCE_LEN],
    stage: Stage,
    next_exchange: u32,
    next_send: Instant,
    timeout: Duration,
    replied: bool,
}

impl Handshake {
    fn restart(&mut self, now: Instant) {
        self.nonce = random_bytes();
        self.stage = Stage::Hello;
        self.timeout = HANDSHAKE_TIMEOUT;
        self.next_send = now;
    }
}

#[derive(Debug)]
enum Phase {
    /// Waiting for OPEN_RESULT.
    Opening {
        buf: Vec<u8>,
    },
    Connected,
    /// The server refused; our FIN is queued and incoming bytes are dropped.
    Failed,
}

#[derive(Debug)]
struct ClientStream {
    pipe: Pipe,
    key: u64,
    phase: Phase,
    deadline: Instant,
}

impl HasPipe for ClientStream {
    fn pipe(&mut self) -> &mut Pipe {
        &mut self.pipe
    }
}

enum Step {
    Continue,
    Abort(u8),
}

struct Session {
    id: u32,
    next_exchange: u32,
    highest_response: Option<u32>,
    last_response: Instant,
    depth: usize,
    streams: BTreeMap<u32, ClientStream>,
    keys: HashMap<u64, u32>,
    tombstones: Tombstones,
    resets: ResetRepeats,
    /// Re-ACKs for late frames on gracefully closed streams.
    late_acks: Vec<StreamAck>,
    next_stream: u32,
    rtt: Rtt,
    last_activity: Instant,
    last_query: Instant,
    more_pending: bool,
    /// Upload work waited for a pipeline slot since the last response.
    slot_wanted: bool,
    cursor: u32,
    budget: Budget,
    reverse: Streams,
}

impl Session {
    fn new(
        id: u32,
        now: Instant,
        sizes: Sizes,
        key_source: Arc<AtomicU64>,
        reverse_budget: Budget,
    ) -> Session {
        Session {
            id,
            next_exchange: 1,
            highest_response: None,
            last_response: now,
            depth: START_DEPTH,
            streams: BTreeMap::new(),
            keys: HashMap::new(),
            tombstones: Tombstones::default(),
            resets: ResetRepeats::default(),
            late_acks: Vec::new(),
            next_stream: 1,
            rtt: Rtt::default(),
            last_activity: now,
            last_query: now,
            more_pending: false,
            slot_wanted: false,
            cursor: 0,
            budget: Budget::unlimited(),
            reverse: Streams::new(false, sizes.u, sizes.d, reverse_budget, key_source),
        }
    }

    fn admit(&mut self, open: PendingOpen, sizes: &Sizes, now: Instant) -> bool {
        let id = self.next_stream;
        let Some(next) = id.checked_add(1).filter(|&next| next < reverse::FIRST_ID) else {
            return false;
        };
        self.next_stream = next;
        let mut pipe = Pipe::new(now, sizes.d);
        pipe.writer = Some(open.writer);
        pipe.permits = Some(open.permits);
        let used = pipe.push_record(&open.target.encode(), sizes.u);
        pipe.grant_initial_permits(used);
        debug!(stream = id, target = %open.target, "opening stream");
        let phase = Phase::Opening { buf: Vec::new() };
        self.streams.insert(
            id,
            ClientStream {
                pipe,
                key: open.key,
                phase,
                deadline: open.deadline,
            },
        );
        self.keys.insert(open.key, id);
        self.last_activity = now;
        true
    }

    fn remove(&mut self, id: u32) -> Option<ClientStream> {
        let stream = self.streams.remove(&id)?;
        self.keys.remove(&stream.key);
        Some(stream)
    }

    fn reset_stream(&mut self, id: u32, reason: u8, now: Instant) {
        if self.remove(id).is_some() {
            debug!(stream = id, reason, "resetting stream");
        }
        self.tombstones.insert(id, Tombstone::Reset(reason), now);
        self.resets.push(id, reason, now);
    }

    fn close(&mut self, id: u32, now: Instant) {
        let Some(stream) = self.remove(id) else {
            return;
        };
        debug!(stream = id, "stream closed");
        if let Ok(ack) = stream.pipe.ack(id) {
            self.tombstones.insert(id, Tombstone::Closed(ack), now);
        }
    }

    fn has_upload_work(&self, now: Instant) -> bool {
        self.reverse.pending(now)
            || self.resets.due(now)
            || !self.late_acks.is_empty()
            || self
                .streams
                .values()
                .any(|s| s.pipe.send.has_sendable() || s.pipe.ack_dirty)
    }

    /// When the next session query should go out, if one is needed.
    fn query_due(&self, in_flight: usize, now: Instant) -> Option<Instant> {
        if in_flight >= self.depth {
            return None;
        }
        // Spread queries across the round trip rather than bursting.
        let pace = self.rtt.srtt().unwrap_or(DEFAULT_PACE_RTT) / self.depth as u32;
        let paced = if in_flight == 0 {
            now
        } else {
            self.last_query + pace
        };
        if self.has_upload_work(now) || self.more_pending {
            return Some(paced);
        }
        if in_flight > 0 {
            return None;
        }
        let idle = now.saturating_duration_since(self.last_activity);
        let interval = match () {
            // Poll for server-initiated opens even with no local connections.
            _ if self.streams.is_empty() => Duration::from_secs(1),
            _ if idle < Duration::from_secs(10) => Duration::from_secs(1),
            _ if idle < Duration::from_secs(60) => Duration::from_secs(5),
            _ => KEEPALIVE,
        };
        Some(self.last_query + interval)
    }

    /// Pack the next query envelope, or `None` once exchange IDs run out.
    fn build_query(&mut self, sizes: &Sizes, now: Instant) -> Option<(Envelope, Vec<(u32, u32)>)> {
        let exchange = self.next_exchange;
        self.next_exchange = exchange.checked_add(1)?;
        let lag = self
            .highest_response
            .map_or(LAG_UNKNOWN, |h| (exchange - h).min(255) as u8);
        let mut packer = Packer::new(sizes.max_query_envelope - CLIENT_HEADER_LEN);
        self.reverse.pack_acks(&mut packer, now, ACK_BATCH);
        self.resets.pack(&mut packer, now);
        while let Some(ack) = self.late_acks.pop() {
            if !packer.push(Frame::StreamAck(ack)) {
                self.late_acks.push(ack);
                break;
            }
        }
        let mut broken = pack_acks(&mut self.streams, &mut packer, ACK_BATCH);
        // Alternate direction priority so a busy forward stream cannot starve
        // reverse SOCKS. Share the query's total data-stream budget.
        let count = |carried: &Vec<(u32, u32)>| {
            carried
                .iter()
                .map(|&(id, _)| id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        };
        let mut carried = if exchange.is_multiple_of(2) {
            self.reverse
                .pack_data(&mut packer, exchange, sizes.max_data_streams, now)
        } else {
            Vec::new()
        };
        carried.extend(pack_data(
            &mut self.streams,
            &mut self.cursor,
            &mut packer,
            exchange,
            sizes.max_data_streams.saturating_sub(count(&carried)),
            now,
        ));
        if !exchange.is_multiple_of(2) {
            carried.extend(self.reverse.pack_data(
                &mut packer,
                exchange,
                sizes.max_data_streams.saturating_sub(count(&carried)),
                now,
            ));
        }
        broken.extend(pack_acks(&mut self.streams, &mut packer, usize::MAX));
        self.reverse.pack_acks(&mut packer, now, usize::MAX);
        for id in broken {
            self.reset_stream(id, reset::EXHAUSTED, now);
        }
        self.last_query = now;
        Some((
            Envelope::client(self.id, exchange, lag, packer.into_frames()),
            carried,
        ))
    }

    /// Apply a validated response's frames. Returns whether new download
    /// data arrived.
    fn apply(&mut self, frames: Vec<Frame>, now: Instant) -> bool {
        let mut got_data = false;
        for frame in frames {
            if reverse::is_reverse(&frame) {
                let available = MAX_STREAMS.saturating_sub(self.streams.len() + self.reverse.len());
                got_data |= self.reverse.apply(frame, now, available);
                continue;
            }
            match frame {
                Frame::StreamAck(ack) => {
                    if let Some(stream) = self.streams.get_mut(&ack.stream)
                        && stream.pipe.on_ack(&ack, now).is_err()
                    {
                        self.reset_stream(ack.stream, reset::PROTOCOL, now);
                    }
                }
                Frame::Segment {
                    stream,
                    seq,
                    payload,
                } => got_data |= self.on_stream_frame(stream, seq, Some(&payload), now),
                Frame::Fin { stream, seq } => {
                    got_data |= self.on_stream_frame(stream, seq, None, now)
                }
                Frame::Reset { stream, reason } if self.remove(stream).is_some() => {
                    debug!(stream, reason, "stream reset by server");
                    self.tombstones
                        .insert(stream, Tombstone::Reset(reset::UNKNOWN_STREAM), now);
                }
                _ => {}
            }
        }
        got_data
    }

    fn on_stream_frame(&mut self, id: u32, seq: u32, payload: Option<&[u8]>, now: Instant) -> bool {
        let Some(stream) = self.streams.get_mut(&id) else {
            match self.tombstones.get(id, now) {
                Some(Tombstone::Closed(ack)) => {
                    if !self.late_acks.contains(&ack) {
                        self.late_acks.push(ack);
                    }
                }
                Some(Tombstone::Reset(reason)) => self.resets.push(id, reason, now),
                None => self.resets.push(id, reset::UNKNOWN_STREAM, now),
            }
            return false;
        };
        let result = match payload {
            Some(payload) => stream.pipe.on_segment(seq, payload, &self.budget),
            None => stream.pipe.on_fin(seq),
        };
        match result {
            Ok(admit) => admit == Admit::Accepted,
            Err(_) => {
                self.reset_stream(id, reset::PROTOCOL, now);
                false
            }
        }
    }

    fn drive(&mut self, id: u32, now: Instant) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let pipe = &mut stream.pipe;
        let mut next_phase = None;
        let step = match &mut stream.phase {
            Phase::Opening { buf } => loop {
                match pipe.take_one(now) {
                    None => break Step::Continue,
                    Some(Delivery::Fin) => break Step::Abort(reset::PROTOCOL),
                    Some(Delivery::Data(chunk)) => {
                        buf.extend_from_slice(chunk.as_ref());
                        match OpenResult::parse(buf) {
                            Err(_) => break Step::Abort(reset::PROTOCOL),
                            Ok(None) if buf.len() > MAX_OPEN_RECORD => {
                                break Step::Abort(reset::PROTOCOL);
                            }
                            Ok(None) => {}
                            Ok(Some((result, used))) => {
                                let writer =
                                    pipe.writer.take().expect("opening streams have a writer");
                                // The reply queue is empty, so these cannot fail.
                                let _ = writer.try_send(WriteCmd::Reply(result));
                                if result.status == status::SUCCEEDED {
                                    if used < buf.len() {
                                        let _ = writer.try_send(WriteCmd::Data(Chunk::new(
                                            buf[used..].to_vec(),
                                        )));
                                    }
                                    pipe.writer = Some(writer);
                                    next_phase = Some(Phase::Connected);
                                } else {
                                    debug!(
                                        stream = id,
                                        status = result.status,
                                        "server could not connect"
                                    );
                                    pipe.push_fin();
                                    next_phase = Some(Phase::Failed);
                                }
                                break Step::Continue;
                            }
                        }
                    }
                }
            },
            Phase::Connected => Step::Continue,
            Phase::Failed => {
                while pipe.take_one(now).is_some() {}
                Step::Continue
            }
        };
        if let Some(phase) = next_phase {
            stream.phase = phase;
        }
        if matches!(stream.phase, Phase::Connected) {
            stream.pipe.deliver_to_writer(now);
        }
        match step {
            Step::Abort(reason) => self.reset_stream(id, reason, now),
            Step::Continue if stream.pipe.finished() => self.close(id, now),
            Step::Continue => {}
        }
    }

    fn drive_all(&mut self, now: Instant) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.drive(id, now);
        }
    }

    fn on_io(&mut self, key: u64, kind: IoKind, now: Instant) {
        let Some(&id) = self.keys.get(&key) else {
            return;
        };
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        match kind {
            IoKind::Data(chunk) => {
                self.last_activity = now;
                if !stream.pipe.push_data(chunk) {
                    return self.reset_stream(id, reset::EXHAUSTED, now);
                }
            }
            IoKind::Eof => {
                self.last_activity = now;
                if !stream.pipe.push_fin() {
                    return self.reset_stream(id, reset::EXHAUSTED, now);
                }
            }
            IoKind::ReadError | IoKind::WriteError | IoKind::Closed => {
                return self.reset_stream(id, reset::LOCAL_ABORT, now);
            }
            _ => {}
        }
        self.drive(id, now);
    }

    fn timers(&mut self, now: Instant) {
        let rto = self.rtt.rto();
        self.reverse.timers(now, rto, None);
        let mut aborts = Vec::new();
        for (&id, stream) in self.streams.iter_mut() {
            stream.pipe.send.expire(now, rto);
            stream.pipe.credit_repeat_due(now);
            if stream.pipe.stalled(now) {
                aborts.push((id, reset::STALLED));
            } else if matches!(stream.phase, Phase::Opening { .. }) && now >= stream.deadline {
                if let Some(writer) = &stream.pipe.writer {
                    let _ =
                        writer.try_send(WriteCmd::Reply(OpenResult::failure(status::TIMED_OUT)));
                }
                aborts.push((id, reset::OPEN_DEADLINE));
            }
        }
        for (id, reason) in aborts {
            self.reset_stream(id, reason, now);
        }
        self.tombstones.prune(now);
    }

    fn next_deadline(&self, in_flight: usize, now: Instant) -> Option<Instant> {
        let rto = self.rtt.rto();
        let streams = self
            .streams
            .values()
            .filter_map(|s| s.pipe.next_deadline(rto));
        [
            self.query_due(in_flight, now),
            self.resets.next_deadline(now),
            self.reverse.next_deadline(now, rto),
        ]
        .into_iter()
        .flatten()
        .chain(streams)
        .min()
    }
}

enum State {
    Idle,
    Handshake(Handshake),
    Established(Box<Session>),
}

/// The client's sans-I/O core: SOCKS opens, TCP events, and DNS responses
/// in; DNS queries out.
pub struct ClientCore {
    transport: Transport,
    sizes: Sizes,
    state: State,
    pending: VecDeque<PendingOpen>,
    backoff_until: Option<Instant>,
    /// Unsupported protocol version or replaced by a newer client; never retry.
    fatal: bool,
    reverse_keys: Arc<AtomicU64>,
    reverse_budget: Budget,
}

impl ClientCore {
    pub fn new(domain: TunnelDomain, key: SharedSecret) -> Result<ClientCore, String> {
        let sizes = domain.sizes()?;
        Ok(ClientCore {
            transport: Transport {
                domain,
                key,
                crypto: None,
                outstanding: HashMap::new(),
                out: Vec::new(),
                generation: 0,
            },
            sizes,
            state: State::Idle,
            pending: VecDeque::new(),
            backoff_until: None,
            fatal: false,
            reverse_keys: Arc::new(AtomicU64::new(1)),
            reverse_budget: Budget::new(BUFFER_LIMIT),
        })
    }

    pub fn sizes(&self) -> Sizes {
        self.sizes
    }

    /// Current pipeline depth and queries in flight, once established.
    pub fn pipeline(&self) -> Option<(usize, usize)> {
        match &self.state {
            State::Established(session) => Some((session.depth, self.transport.in_flight())),
            _ => None,
        }
    }

    pub fn established(&self) -> Option<u32> {
        match &self.state {
            State::Established(session) => Some(session.id),
            _ => None,
        }
    }

    pub fn handle_io(&mut self, event: IoEvent, now: Instant) {
        if event.key & reverse::KEY_BIT != 0 {
            if let State::Established(session) = &mut self.state {
                session.reverse.handle_io(event, now);
            }
            return;
        }
        match event.kind {
            IoKind::Open {
                target,
                writer,
                permits,
            } => {
                let open = PendingOpen {
                    key: event.key,
                    target,
                    writer,
                    permits,
                    deadline: now + OPEN_DEADLINE,
                };
                if self.fatal || self.pending.len() >= MAX_PENDING_OPENS {
                    open.fail(status::FAILURE);
                } else {
                    self.pending.push_back(open);
                }
            }
            kind => {
                if matches!(kind, IoKind::Closed) {
                    self.pending.retain(|open| open.key != event.key);
                }
                if let State::Established(session) = &mut self.state {
                    session.on_io(event.key, kind, now);
                }
            }
        }
    }

    pub fn handle_datagram(&mut self, packet: &[u8], now: Instant) {
        let Some(id) = packet.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
            return;
        };
        let Some(query) = self.transport.outstanding.get(&id) else {
            return;
        };
        let mut payload = match dns::parse_response(packet, &query.qname) {
            Ok(payload) => payload,
            Err(ResponseError::Rcode) => {
                let query = self.transport.outstanding.remove(&id).expect("present");
                debug!(exchange = query.exchange, "resolver returned an error");
                self.query_lost(&query);
                return;
            }
            Err(ResponseError::Malformed) => return,
        };
        if query.generation != self.transport.generation {
            return;
        }
        // Public errors have a dedicated existing flag bit, not a tag/nonce.
        // They are explicitly untrusted and can only tear down/retry a session.
        if query.kind == Kind::Session && payload.first().is_none_or(|b| b & FLAG_PLAIN_ERROR == 0)
        {
            let Some(crypto) = &self.transport.crypto else {
                return;
            };
            if crypto
                .apply(&mut payload, Direction::ServerToClient)
                .is_none()
            {
                return;
            }
        }
        let Ok(env) = Envelope::decode(&payload, Direction::ServerToClient) else {
            return;
        };
        if env.exchange_id != query.exchange {
            return;
        }
        let query = self.transport.outstanding.remove(&id).expect("present");
        if query.generation != self.transport.generation {
            return;
        }
        match query.kind {
            Kind::Hello | Kind::Echo => self.on_handshake_response(&query, env, now),
            Kind::Session => self.on_session_response(query, env, now),
        }
    }

    /// A timed-out or failed session query halves the pipeline depth.
    fn query_lost(&mut self, query: &Outstanding) {
        if query.kind == Kind::Session
            && query.generation == self.transport.generation
            && let State::Established(session) = &mut self.state
        {
            session.depth = (session.depth / 2).max(MIN_DEPTH);
        }
    }

    fn on_handshake_response(&mut self, query: &Outstanding, env: Envelope, now: Instant) {
        let State::Handshake(handshake) = &mut self.state else {
            return;
        };
        if env.session_id != 0 {
            return;
        }
        handshake.replied = true;
        let at_hello = matches!(handshake.stage, Stage::Hello);
        match (&env.frames[0], at_hello, query.kind) {
            (
                &Frame::Challenge {
                    server_nonce,
                    u,
                    d,
                    cookie,
                },
                true,
                Kind::Hello,
            ) => {
                if (usize::from(u), usize::from(d)) != (self.sizes.u, self.sizes.d) {
                    error!(
                        server_u = u,
                        server_d = d,
                        u = self.sizes.u,
                        d = self.sizes.d,
                        "server segment sizes differ from ours; check that --domain matches the server"
                    );
                    return self.fail_handshake(now);
                }
                handshake.stage = Stage::Echo {
                    server_nonce,
                    cookie,
                };
                handshake.timeout = HANDSHAKE_TIMEOUT;
                handshake.next_send = now;
            }
            (&Frame::Accept { session_id, proof }, false, Kind::Echo) if session_id != 0 => {
                let Stage::Echo {
                    server_nonce,
                    cookie,
                } = &handshake.stage
                else {
                    return;
                };
                let input = CookieInput {
                    domain_wire: self.transport.domain.wire(),
                    client_nonce: &handshake.nonce,
                    server_nonce,
                    u: self.sizes.u as u16,
                    d: self.sizes.d as u16,
                };
                if !self
                    .transport
                    .key
                    .verify_server(&input, cookie, session_id, &proof)
                {
                    debug!("server handshake authentication failed");
                    return;
                }
                self.transport.crypto =
                    Some(self.transport.key.session_keys(&input, cookie, session_id));
                info!(session = format!("{session_id:08x}"), "session established");
                self.transport.generation += 1;
                self.state = State::Established(Box::new(Session::new(
                    session_id,
                    now,
                    self.sizes,
                    self.reverse_keys.clone(),
                    self.reverse_budget.clone(),
                )));
            }
            (&Frame::SessionError { reason }, _, _) => match reason {
                session_error::REPLACED => {
                    warn!(
                        "a newer client owns the reverse proxy; restart this client to reconnect"
                    );
                    self.fatal = true;
                    self.fail_handshake(now);
                }
                session_error::BUSY => {
                    warn!("server busy; retrying later");
                    self.fail_handshake(now);
                }
                session_error::UNSUPPORTED_VERSION => {
                    error!("server does not support this protocol version");
                    self.fatal = true;
                    self.fail_handshake(now);
                }
                session_error::HANDSHAKE_EXPIRED => {
                    debug!("handshake cookie expired; restarting");
                    handshake.restart(now);
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn fail_handshake(&mut self, now: Instant) {
        for open in self.pending.drain(..) {
            open.fail(status::FAILURE);
        }
        self.state = State::Idle;
        self.transport.crypto = None;
        self.transport.generation += 1;
        self.backoff_until = Some(now + HANDSHAKE_BACKOFF);
    }

    fn fail_session(&mut self) {
        if let State::Established(session) = mem::replace(&mut self.state, State::Idle) {
            warn!(
                session = format!("{:08x}", session.id),
                streams = session.streams.len(),
                "session lost; failing its connections"
            );
        }
        self.transport.crypto = None;
        self.transport.generation += 1;
    }

    fn on_session_response(&mut self, query: Outstanding, env: Envelope, now: Instant) {
        let State::Established(session) = &mut self.state else {
            return;
        };
        if env.session_id != session.id {
            return;
        }
        if let [Frame::SessionError { reason }] = env.frames[..] {
            match reason {
                session_error::UNKNOWN_SESSION => self.fail_session(),
                session_error::REPLACED => {
                    warn!(
                        "a newer client owns the reverse proxy; restart this client to reconnect"
                    );
                    self.fatal = true;
                    self.fail_session();
                    for open in self.pending.drain(..) {
                        open.fail(status::FAILURE);
                    }
                }
                session_error::UNSUPPORTED_VERSION => {
                    error!("server does not support this protocol version");
                    self.fatal = true;
                    self.fail_session();
                }
                _ => {}
            }
            return;
        }
        session
            .rtt
            .sample(now.saturating_duration_since(query.sent_at));
        session.highest_response = Some(
            session
                .highest_response
                .map_or(query.exchange, |h| h.max(query.exchange)),
        );
        session.last_response = now;
        let got_data = session.apply(env.frames, now);

        // Upload loss: frames this query carried that the response's
        // STREAM_ACKs do not cover were rejected.
        let rto = session.rtt.rto();
        for &(id, seq) in &query.carried {
            session.reverse.mark_lost(id, seq, query.exchange, now, rto);
            if let Some(stream) = session.streams.get_mut(&id) {
                stream.pipe.send.mark_lost(seq, query.exchange, now, rto);
            }
        }
        // Responses three or more exchanges later prove older queries lost.
        let generation = self.transport.generation;
        let lost: Vec<u16> = self
            .transport
            .outstanding
            .iter()
            .filter(|(_, o)| o.kind == Kind::Session && o.generation == generation)
            .filter(|(_, o)| o.exchange.saturating_add(LOSS_REORDER) <= query.exchange)
            .map(|(&id, _)| id)
            .collect();
        for id in lost {
            let old = self.transport.outstanding.remove(&id).expect("listed");
            for (stream, seq) in old.carried {
                session
                    .reverse
                    .mark_lost(stream, seq, old.exchange, now, rto);
                if let Some(stream) = session.streams.get_mut(&stream) {
                    stream.pipe.send.mark_lost(seq, old.exchange, now, rto);
                }
            }
        }

        session.more_pending = env.more_pending;
        if env.more_pending || got_data {
            session.last_activity = now;
        }
        session.drive_all(now);
        if env.more_pending || mem::take(&mut session.slot_wanted) {
            session.depth = (session.depth + 1).min(MAX_DEPTH);
        } else if now >= session.last_activity + DEPTH_DECAY_IDLE && session.depth > START_DEPTH {
            session.depth -= 1;
        }
    }

    /// Run timers and emit any queries now due.
    pub fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let expired: Vec<u16> = self
            .transport
            .outstanding
            .iter()
            .filter(|(_, o)| now >= o.deadline)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            let query = self.transport.outstanding.remove(&id).expect("listed");
            self.query_lost(&query);
        }
        while self
            .pending
            .front()
            .is_some_and(|open| now >= open.deadline || open.writer.is_closed())
        {
            let open = self.pending.pop_front().expect("checked");
            open.fail(status::FAILURE);
        }
        self.pending.retain(|open| !open.writer.is_closed());

        if matches!(self.state, State::Idle)
            && !self.fatal
            && self.backoff_until.is_none_or(|until| now >= until)
        {
            debug!("starting handshake");
            self.transport.generation += 1;
            let mut handshake = Handshake {
                started: now,
                nonce: [0; NONCE_LEN],
                stage: Stage::Hello,
                next_exchange: 1,
                next_send: now,
                timeout: HANDSHAKE_TIMEOUT,
                replied: false,
            };
            handshake.restart(now);
            self.state = State::Handshake(handshake);
        }
        match &mut self.state {
            State::Idle => {}
            State::Handshake(_) => self.drive_handshake(now),
            State::Established(_) => self.drive_session(now),
        }
        mem::take(&mut self.transport.out)
    }

    fn drive_handshake(&mut self, now: Instant) {
        let State::Handshake(handshake) = &mut self.state else {
            return;
        };
        if now >= handshake.started + HANDSHAKE_TOTAL {
            if handshake.replied {
                warn!("handshake timed out");
            } else {
                warn!(
                    "no valid reply during the handshake: probable --domain, --resolver, or shared-secret mismatch"
                );
            }
            return self.fail_handshake(now);
        }
        if now < handshake.next_send {
            return;
        }
        let (frame, kind) = match &handshake.stage {
            Stage::Hello => (
                Frame::Hello {
                    client_nonce: handshake.nonce,
                },
                Kind::Hello,
            ),
            &Stage::Echo {
                server_nonce,
                cookie,
            } => (
                Frame::CookieEcho {
                    client_nonce: handshake.nonce,
                    server_nonce,
                    cookie,
                    proof: self.transport.key.client_proof(
                        &CookieInput {
                            domain_wire: self.transport.domain.wire(),
                            client_nonce: &handshake.nonce,
                            server_nonce: &server_nonce,
                            u: self.sizes.u as u16,
                            d: self.sizes.d as u16,
                        },
                        &cookie,
                    ),
                },
                Kind::Echo,
            ),
        };
        let exchange = handshake.next_exchange;
        handshake.next_exchange += 1;
        let timeout = handshake.timeout;
        handshake.next_send = now + timeout;
        handshake.timeout = (timeout * 2).min(MAX_HANDSHAKE_TIMEOUT);
        let env = Envelope::client(0, exchange, LAG_UNKNOWN, vec![frame]);
        self.transport
            .send(&env, kind, now + timeout, Vec::new(), now);
    }

    fn drive_session(&mut self, now: Instant) {
        let State::Established(session) = &mut self.state else {
            return;
        };
        if now >= session.last_response + SESSION_EXPIRY {
            warn!("no valid response for 60 s");
            return self.fail_session();
        }
        while session.streams.len() + session.reverse.len() < MAX_STREAMS
            && let Some(open) = self.pending.pop_front()
        {
            if !session.admit(open, &self.sizes, now) {
                return self.fail_session();
            }
        }
        session.timers(now);
        session.drive_all(now);
        loop {
            match session.query_due(self.transport.in_flight(), now) {
                Some(at) if at <= now => {}
                _ => {
                    // Held back by depth or pacing: the pipeline is too shallow.
                    if session.has_upload_work(now) {
                        session.slot_wanted = true;
                    }
                    break;
                }
            }
            let Some((env, carried)) = session.build_query(&self.sizes, now) else {
                info!("exchange IDs exhausted; starting a new session");
                return self.fail_session();
            };
            let deadline = now + session.rtt.rto();
            self.transport
                .send(&env, Kind::Session, deadline, carried, now);
        }
    }

    /// Destination connection attempts requested by reverse streams.
    pub fn take_actions(&mut self) -> Vec<Action> {
        match &mut self.state {
            State::Established(session) => session.reverse.take_actions(),
            _ => Vec::new(),
        }
    }

    /// When `poll` next needs to run.
    pub fn next_deadline(&self, now: Instant) -> Instant {
        let mut at = now + MAX_SLEEP;
        for query in self.transport.outstanding.values() {
            at = at.min(query.deadline);
        }
        match &self.state {
            State::Idle => {
                if !self.fatal
                    && let Some(until) = self.backoff_until
                {
                    at = at.min(until);
                }
            }
            State::Handshake(handshake) => at = at.min(handshake.next_send),
            State::Established(session) => {
                if let Some(due) = session.next_deadline(self.transport.in_flight(), now) {
                    at = at.min(due);
                }
            }
        }
        at.max(now)
    }
}

pub struct ClientOptions {
    pub domain: TunnelDomain,
    pub key: SharedSecret,
}

/// The SOCKS listener and the DNS query socket.
pub struct Client {
    socket: UdpSocket,
    listener: TcpListener,
    core: ClientCore,
}

impl Client {
    pub async fn bind(
        listen: SocketAddr,
        resolver: SocketAddr,
        options: ClientOptions,
    ) -> io::Result<Client> {
        let core = ClientCore::new(options.domain, options.key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let local: SocketAddr = if resolver.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = UdpSocket::bind(local).await?;
        // A connected socket makes the kernel drop datagrams from other sources.
        socket.connect(resolver).await?;
        let listener = TcpListener::bind(listen).await?;
        Ok(Client {
            socket,
            listener,
            core,
        })
    }

    pub fn socks_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(mut self) -> io::Result<()> {
        let (events_tx, mut events) = mpsc::channel(1024);
        let segment = self.core.sizes().u;
        let listener = self.listener;
        let accept_events = events_tx.clone();
        let accept = tokio::spawn(async move {
            let mut next_key = 1u64;
            loop {
                match listener.accept().await {
                    Ok((tcp, peer)) => {
                        debug!(%peer, "SOCKS connection");
                        let _ = tcp.set_nodelay(true);
                        tokio::spawn(socks::serve(tcp, next_key, accept_events.clone(), segment));
                        next_key += 1;
                    }
                    Err(e) => {
                        warn!(%e, "SOCKS accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        let _abort_accept = AbortOnDrop(accept);
        let mut buf = vec![0u8; 65535];
        // Establish a session without waiting for a local SOCKS request.
        for packet in self.core.poll(now()) {
            self.socket.send(&packet).await?;
        }
        loop {
            let deadline = tokio::time::Instant::from_std(self.core.next_deadline(now()));
            tokio::select! {
                received = self.socket.recv(&mut buf) => match received {
                    Ok(n) => self.core.handle_datagram(&buf[..n], now()),
                    Err(e) => debug!(%e, "receive failed"),
                },
                Some(event) = events.recv() => self.core.handle_io(event, now()),
                _ = tokio::time::sleep_until(deadline) => {}
            }
            for packet in self.core.poll(now()) {
                if let Err(e) = self.socket.send(&packet).await {
                    debug!(%e, "send failed");
                }
            }
            for action in self.core.take_actions() {
                // Reverse SOCKS deliberately reaches the client's private network.
                socks::spawn_dial(
                    action,
                    events_tx.clone(),
                    segment,
                    self.core.reverse_budget.clone(),
                    true,
                );
            }
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
