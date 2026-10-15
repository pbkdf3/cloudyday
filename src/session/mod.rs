//! Session machinery shared by client and server: per-stream pipes joining
//! the ARQ halves to TCP bridges, buffer accounting, tombstones, RESET
//! repeats, and frame packing (§5, §6, §7.5, §9).

pub mod client;
mod reverse;
pub mod server;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore, mpsc};

use crate::arq::{
    AckError, AckOutcome, Admit, Delivery, Outbound, RecvError, RecvStream, SendStream,
};
use crate::wire::{Frame, OpenResult, StreamAck, Target, WINDOW};

pub const OPEN_DEADLINE: Duration = Duration::from_secs(30);
pub const STALL_DEADLINE: Duration = Duration::from_secs(120);
pub const SESSION_EXPIRY: Duration = Duration::from_secs(60);
pub const KEEPALIVE: Duration = Duration::from_secs(15);
pub const MAX_STREAMS: usize = 64;
const TOMBSTONE_LIFETIME: Duration = Duration::from_secs(60);
const MAX_TOMBSTONES: usize = 256;
const RESET_INTERVAL: Duration = Duration::from_secs(1);
const RESET_REPEAT_FOR: Duration = Duration::from_secs(5);
const CREDIT_REPEAT_INTERVAL: Duration = Duration::from_secs(1);
const CREDIT_REPEATS: u32 = 5;
/// STREAM_ACKs packed ahead of data in one envelope; the rest follow data.
const ACK_BATCH: usize = 4;
/// Chunks queued to a TCP writer. Handing a chunk over counts as consumption.
pub const WRITE_QUEUE: usize = 8;

pub fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Aggregate byte limit shared by every buffer that holds protocol data.
#[derive(Clone, Debug)]
pub struct Budget(Arc<BudgetInner>);

#[derive(Debug)]
struct BudgetInner {
    used: AtomicUsize,
    limit: usize,
    released: Notify,
}

impl Budget {
    pub fn new(limit: usize) -> Budget {
        Budget(Arc::new(BudgetInner {
            used: AtomicUsize::new(0),
            limit,
            released: Notify::new(),
        }))
    }

    pub fn unlimited() -> Budget {
        Budget::new(usize::MAX)
    }

    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Relaxed)
    }

    pub fn try_reserve(&self, n: usize) -> Option<Reservation> {
        self.0
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(n).filter(|&total| total <= self.0.limit)
            })
            .ok()
            .map(|_| Reservation {
                budget: self.clone(),
                n,
            })
    }

    /// Wait until `n` bytes can be reserved.
    pub async fn reserve(&self, n: usize) -> Reservation {
        loop {
            let notified = self.0.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(reservation) = self.try_reserve(n) {
                return reservation;
            }
            notified.await;
        }
    }
}

/// Bytes held against a [`Budget`], released on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Budget,
    n: usize,
}

impl Reservation {
    pub fn shrink(&mut self, n: usize) {
        if n < self.n {
            self.budget.0.used.fetch_sub(self.n - n, Ordering::AcqRel);
            self.n = n;
            self.budget.0.released.notify_waiters();
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.n, Ordering::AcqRel);
        self.budget.0.released.notify_waiters();
    }
}

/// Stream bytes, optionally holding their buffer reservation.
#[derive(Debug)]
pub struct Chunk {
    data: Vec<u8>,
    _hold: Option<Reservation>,
}

impl Chunk {
    pub fn new(data: Vec<u8>) -> Chunk {
        Chunk { data, _hold: None }
    }

    pub fn reserved(data: Vec<u8>, reservation: Reservation) -> Chunk {
        Chunk {
            data,
            _hold: Some(reservation),
        }
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Commands from a session to the task bridging one TCP connection.
#[derive(Debug)]
pub enum WriteCmd {
    /// The SOCKS reply to write before bridging.
    Reply(OpenResult),
    Data(Chunk),
    /// Shut down the TCP write half after earlier data.
    Shutdown,
}

/// Reports from TCP tasks to the session core, keyed by connection.
#[derive(Debug)]
pub struct IoEvent {
    pub key: u64,
    pub kind: IoKind,
}

#[derive(Debug)]
pub enum IoKind {
    /// A SOCKS CONNECT ready to open a stream.
    Open {
        target: Target,
        writer: mpsc::Sender<WriteCmd>,
        permits: Arc<Semaphore>,
    },
    /// The SOCKS connection closed before its reply.
    Closed,
    /// The destination connected.
    Connected {
        writer: mpsc::Sender<WriteCmd>,
        permits: Arc<Semaphore>,
        local: SocketAddr,
    },
    /// Dialing failed with this OPEN_RESULT status.
    DialFailed(u8),
    Data(Chunk),
    Eof,
    ReadError,
    Written,
    WriteError,
}

#[derive(Debug)]
struct CreditRepeat {
    prev_limit: u32,
    next_at: Instant,
    sent: u32,
}

/// Both directions of one stream plus its link to a TCP bridge.
#[derive(Debug)]
pub struct Pipe {
    pub send: SendStream<Chunk>,
    pub recv: RecvStream<Chunk>,
    /// Receive state changed since a STREAM_ACK was last packed.
    pub ack_dirty: bool,
    credit_repeat: Option<CreditRepeat>,
    last_progress: Instant,
    pub writer: Option<mpsc::Sender<WriteCmd>>,
    pub permits: Option<Arc<Semaphore>>,
    max_payload: usize,
}

impl Pipe {
    pub fn new(now: Instant, max_payload: usize) -> Pipe {
        Pipe {
            send: SendStream::default(),
            recv: RecvStream::default(),
            ack_dirty: false,
            credit_repeat: None,
            last_progress: now,
            writer: None,
            permits: None,
            max_payload,
        }
    }

    pub fn ack(&self, stream: u32) -> Result<StreamAck, RecvError> {
        self.recv.ack(stream)
    }

    pub fn on_ack(&mut self, ack: &StreamAck, now: Instant) -> Result<AckOutcome, AckError> {
        let outcome = self.send.apply_ack(ack, now)?;
        if outcome.progressed {
            self.last_progress = now;
        }
        if let Some(permits) = &self.permits
            && outcome.freed_segments > 0
        {
            permits.add_permits(outcome.freed_segments);
        }
        Ok(outcome)
    }

    pub fn on_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
        budget: &Budget,
    ) -> Result<Admit, RecvError> {
        if payload.len() > self.max_payload {
            return Err(RecvError::Violation);
        }
        let store = || {
            budget
                .try_reserve(payload.len())
                .map(|r| Chunk::reserved(payload.to_vec(), r))
        };
        let admit = self.recv.receive_segment(seq, store)?;
        self.received(seq);
        Ok(admit)
    }

    pub fn on_fin(&mut self, seq: u32) -> Result<Admit, RecvError> {
        let admit = self.recv.receive_fin(seq)?;
        self.received(seq);
        Ok(admit)
    }

    fn received(&mut self, seq: u32) {
        // Duplicates and refusals are acknowledged again too.
        self.ack_dirty = true;
        if self
            .credit_repeat
            .as_ref()
            .is_some_and(|r| seq >= r.prev_limit)
        {
            self.credit_repeat = None;
        }
    }

    fn credit_limit(&self) -> u32 {
        self.recv.credit_limit().unwrap_or(u32::MAX)
    }

    /// Note a credit increase; repeat it while the peer appears blocked.
    fn credit_moved(&mut self, before: u32, now: Instant) {
        if self.credit_limit() <= before {
            return;
        }
        self.ack_dirty = true;
        let peer_blocked = self
            .recv
            .highest_seen()
            .is_some_and(|h| h.saturating_add(1) >= before);
        if peer_blocked {
            let prev_limit = self.credit_repeat.as_ref().map_or(before, |r| r.prev_limit);
            self.credit_repeat = Some(CreditRepeat {
                prev_limit,
                next_at: now + CREDIT_REPEAT_INTERVAL,
                sent: 0,
            });
        }
    }

    /// Hand contiguous data to the TCP writer while it has room. Returns
    /// whether FIN was delivered.
    pub fn deliver_to_writer(&mut self, now: Instant) -> bool {
        let before = self.credit_limit();
        let mut fin = false;
        if let Some(writer) = &self.writer {
            while self.recv.deliverable() {
                let Ok(permit) = writer.try_reserve() else {
                    break;
                };
                match self.recv.deliver() {
                    Some(Delivery::Data(chunk)) => permit.send(WriteCmd::Data(chunk)),
                    Some(Delivery::Fin) => {
                        permit.send(WriteCmd::Shutdown);
                        fin = true;
                    }
                    None => break,
                }
            }
        }
        self.credit_moved(before, now);
        fin
    }

    /// Consume one item without a writer (opening records, failed streams).
    pub fn take_one(&mut self, now: Instant) -> Option<Delivery<Chunk>> {
        let before = self.credit_limit();
        let item = self.recv.deliver();
        self.credit_moved(before, now);
        item
    }

    /// Fire a due credit repeat by marking the ACK dirty.
    pub fn credit_repeat_due(&mut self, now: Instant) {
        if let Some(repeat) = &mut self.credit_repeat
            && now >= repeat.next_at
        {
            repeat.sent += 1;
            let interval = if repeat.sent < CREDIT_REPEATS {
                CREDIT_REPEAT_INTERVAL
            } else {
                KEEPALIVE
            };
            repeat.next_at = now + interval;
            self.ack_dirty = true;
        }
    }

    pub fn next_deadline(&self, rto: Duration) -> Option<Instant> {
        let repeat = self.credit_repeat.as_ref().map(|r| r.next_at);
        [repeat, self.send.next_timeout(rto)]
            .into_iter()
            .flatten()
            .min()
    }

    /// Unacknowledged frames with no acknowledgement progress for 120 s.
    /// Idle connections are not stalled.
    pub fn stalled(&self, now: Instant) -> bool {
        self.send.in_flight() && now >= self.last_progress + STALL_DEADLINE
    }

    /// Both FINs are done and every local reliable frame is acknowledged.
    pub fn finished(&self) -> bool {
        self.send.fin_queued() && self.send.all_acked() && self.recv.fin_delivered()
    }

    /// Queue local bytes; the reader already holds a permit for them.
    pub fn push_data(&mut self, chunk: Chunk) -> bool {
        !self.send.fin_queued() && self.send.push(chunk).is_ok()
    }

    pub fn push_fin(&mut self) -> bool {
        self.send.fin_queued() || self.send.push_fin().is_ok()
    }

    /// Queue an opening record as segments of at most `segment` bytes;
    /// returns how many segments it used.
    pub fn push_record(&mut self, record: &[u8], segment: usize) -> usize {
        let mut count = 0;
        for part in record.chunks(segment) {
            self.send
                .push(Chunk::new(part.to_vec()))
                .expect("fresh stream has sequence space");
            count += 1;
        }
        count
    }

    /// Reader permits for a newly linked TCP connection: the window minus
    /// segments already queued for the opening record.
    pub fn grant_initial_permits(&self, used: usize) {
        if let Some(permits) = &self.permits {
            permits.add_permits(WINDOW as usize - used);
        }
    }
}

/// Late-traffic answers for closed or aborted streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tombstone {
    /// Gracefully closed: re-ACK late FINs with the final receive state.
    Closed(StreamAck),
    /// Aborted: answer with RESET.
    Reset(u8),
}

#[derive(Debug, Default)]
pub struct Tombstones {
    map: HashMap<u32, (Instant, Tombstone)>,
    order: VecDeque<u32>,
}

impl Tombstones {
    pub fn insert(&mut self, stream: u32, tombstone: Tombstone, now: Instant) {
        while self.map.len() >= MAX_TOMBSTONES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.map.remove(&oldest);
        }
        self.map
            .insert(stream, (now + TOMBSTONE_LIFETIME, tombstone));
        self.order.push_back(stream);
    }

    pub fn get(&mut self, stream: u32, now: Instant) -> Option<Tombstone> {
        let &(expires, tombstone) = self.map.get(&stream)?;
        if now >= expires {
            self.map.remove(&stream);
            return None;
        }
        Some(tombstone)
    }

    pub fn prune(&mut self, now: Instant) {
        self.map.retain(|_, (expires, _)| now < *expires);
        let map = &self.map;
        self.order.retain(|id| map.contains_key(id));
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// RESETs repeated every second for five seconds.
#[derive(Debug, Default)]
pub struct ResetRepeats {
    items: Vec<PendingReset>,
}

#[derive(Debug)]
struct PendingReset {
    stream: u32,
    reason: u8,
    next_at: Instant,
    until: Instant,
}

impl ResetRepeats {
    pub fn push(&mut self, stream: u32, reason: u8, now: Instant) {
        self.items.retain(|r| r.stream != stream);
        self.items.push(PendingReset {
            stream,
            reason,
            next_at: now,
            until: now + RESET_REPEAT_FOR,
        });
    }

    pub fn due(&self, now: Instant) -> bool {
        self.items.iter().any(|r| now >= r.next_at && now < r.until)
    }

    pub fn pack(&mut self, packer: &mut Packer, now: Instant) {
        self.items.retain(|r| now < r.until);
        for reset in &mut self.items {
            if now >= reset.next_at
                && packer.push(Frame::Reset {
                    stream: reset.stream,
                    reason: reset.reason,
                })
            {
                reset.next_at = now + RESET_INTERVAL;
            }
        }
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.items
            .iter()
            .filter(|r| now < r.until)
            .map(|r| r.next_at)
            .min()
    }
}

/// Token bucket for handshake and SESSION_ERROR rate limits.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

impl TokenBucket {
    pub fn new(rate: f64, burst: f64, now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: burst,
            last: now,
            rate,
            burst,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn full(&self, now: Instant) -> bool {
        self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * self.rate
            >= self.burst
    }
}

/// Whole frames packed into a fixed envelope budget.
#[derive(Debug)]
pub struct Packer {
    frames: Vec<Frame>,
    room: usize,
}

impl Packer {
    pub fn new(room: usize) -> Packer {
        Packer {
            frames: Vec::new(),
            room,
        }
    }

    pub fn push(&mut self, frame: Frame) -> bool {
        let len = frame.encoded_len();
        if len > self.room {
            return false;
        }
        self.room -= len;
        self.frames.push(frame);
        true
    }

    pub fn into_frames(self) -> Vec<Frame> {
        self.frames
    }
}

pub trait HasPipe {
    fn pipe(&mut self) -> &mut Pipe;
}

/// Pack up to `limit` dirty STREAM_ACKs. Streams whose ACK cannot be
/// computed (counter overflow) are returned for reset.
pub fn pack_acks<S: HasPipe>(
    streams: &mut BTreeMap<u32, S>,
    packer: &mut Packer,
    limit: usize,
) -> Vec<u32> {
    let mut packed = 0;
    let mut broken = Vec::new();
    for (&id, stream) in streams.iter_mut() {
        if packed >= limit {
            break;
        }
        let pipe = stream.pipe();
        if !pipe.ack_dirty {
            continue;
        }
        match pipe.ack(id) {
            Ok(ack) => {
                if packer.push(Frame::StreamAck(ack)) {
                    pipe.ack_dirty = false;
                    packed += 1;
                }
            }
            Err(_) => broken.push(id),
        }
    }
    broken
}

/// Round-robin SEGMENT/FIN packing: retransmissions first, then new data.
/// Records `(stream, seq)` for each frame dispatched in `exchange`, and
/// never puts frames from more than `max_streams` streams in one envelope.
pub fn pack_data<S: HasPipe>(
    streams: &mut BTreeMap<u32, S>,
    cursor: &mut u32,
    packer: &mut Packer,
    exchange: u32,
    max_streams: usize,
    now: Instant,
) -> Vec<(u32, u32)> {
    let start = *cursor;
    let ids: Vec<u32> = streams
        .range(start.saturating_add(1)..)
        .chain(streams.range(..=start))
        .map(|(&id, _)| id)
        .collect();
    if let Some(&first) = ids.first() {
        *cursor = first;
    }
    let mut carried = Vec::new();
    let mut used: BTreeSet<u32> = BTreeSet::new();
    for retransmit_pass in [true, false] {
        loop {
            let mut progress = false;
            for &id in &ids {
                if !used.contains(&id) && used.len() >= max_streams {
                    continue;
                }
                let pipe = streams.get_mut(&id).expect("listed above").pipe();
                let (frame, seq) = match pipe.send.next_frame() {
                    Some(Outbound::Segment { seq, payload }) => (
                        Frame::Segment {
                            stream: id,
                            seq,
                            payload: payload.to_vec(),
                        },
                        seq,
                    ),
                    Some(Outbound::Fin { seq }) => (Frame::Fin { stream: id, seq }, seq),
                    None => continue,
                };
                if retransmit_pass && !pipe.send.is_retransmission(seq) {
                    continue;
                }
                if packer.push(frame) {
                    pipe.send.dispatched(seq, now, exchange);
                    carried.push((id, seq));
                    used.insert(id);
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
    }
    carried
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_reservations() {
        let budget = Budget::new(100);
        let a = budget.try_reserve(60).unwrap();
        assert!(budget.try_reserve(41).is_none());
        let mut b = budget.try_reserve(40).unwrap();
        b.shrink(10);
        assert_eq!(budget.used(), 70);
        drop(a);
        let chunk = Chunk::reserved(vec![0; 10], b);
        assert_eq!(budget.used(), 10);
        drop(chunk);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn budget_waits_for_release() {
        let budget = Budget::new(10);
        let held = budget.try_reserve(10).unwrap();
        let waiter = tokio::spawn({
            let budget = budget.clone();
            async move { budget.reserve(5).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(held);
        let got = waiter.await.unwrap();
        assert_eq!(budget.used(), 5);
        drop(got);
    }

    #[test]
    fn tombstones_expire_and_evict() {
        let t0 = Instant::now();
        let mut tombs = Tombstones::default();
        for id in 0..300 {
            tombs.insert(id, Tombstone::Reset(1), t0);
        }
        assert_eq!(tombs.get(0, t0), None, "oldest evicted");
        assert_eq!(tombs.get(299, t0), Some(Tombstone::Reset(1)));
        assert_eq!(tombs.get(299, t0 + TOMBSTONE_LIFETIME), None);
    }

    #[test]
    fn reset_repeats() {
        let t0 = Instant::now();
        let mut resets = ResetRepeats::default();
        resets.push(3, 1, t0);
        let mut sent = 0;
        for ms in (0..7000).step_by(100) {
            let now = t0 + Duration::from_millis(ms);
            let mut packer = Packer::new(100);
            resets.pack(&mut packer, now);
            sent += packer.into_frames().len();
        }
        assert_eq!(sent, 5);
    }

    #[test]
    fn token_bucket() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(10.0, 20.0, t0);
        assert_eq!((0..30).filter(|_| bucket.allow(t0)).count(), 20);
        assert!(bucket.allow(t0 + Duration::from_millis(100)));
        assert!(!bucket.allow(t0 + Duration::from_millis(100)));
    }
}
