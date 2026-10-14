//! Pure selective-repeat state for one direction of one stream (§5, A.5).
//!
//! Nothing here owns sockets, spawns tasks, or reads the clock: callers pass
//! timestamps in and pull frames out.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::wire::{StreamAck, WINDOW};

pub const INITIAL_RTO: Duration = Duration::from_secs(1);
pub const MIN_RTO: Duration = Duration::from_millis(250);
pub const MAX_RTO: Duration = Duration::from_secs(5);

/// Smoothed RTT and RTO (RFC 6298 constants), clamped to 250 ms–5 s.
#[derive(Debug, Clone)]
pub struct Rtt {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
}

impl Default for Rtt {
    fn default() -> Self {
        Rtt {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
        }
    }
}

impl Rtt {
    pub fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt);
                self.rttvar = self.rttvar * 3 / 4 + delta / 4;
                self.srtt = Some(srtt * 7 / 8 + rtt / 8);
            }
        }
        let srtt = self.srtt.expect("set above");
        self.rto =
            (srtt + (self.rttvar * 4).max(Duration::from_millis(10))).clamp(MIN_RTO, MAX_RTO);
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }
}

/// RTO for a frame that has already been retransmitted `retries` times.
pub fn backoff(rto: Duration, retries: u32) -> Duration {
    rto.saturating_mul(1 << retries.min(5)).min(MAX_RTO)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckError {
    /// Acknowledges or SACKs a sequence that was never dispatched.
    Unsent,
    /// Sequence or credit arithmetic would overflow `u32`.
    Overflow,
}

#[derive(Debug, Default)]
pub struct AckOutcome {
    /// Data segments released from retention (FIN excluded).
    pub freed_segments: usize,
    /// Whether cumulative ACK, SACK, or credit moved forward.
    pub progressed: bool,
    /// RTT of the most recently sent newly acknowledged frame that was
    /// never retransmitted.
    pub rtt_sample: Option<Duration>,
}

#[derive(Debug)]
struct Outgoing<P> {
    /// `None` for FIN.
    payload: Option<P>,
    sent_at: Option<Instant>,
    transmissions: u32,
    /// Exchange that carried the latest transmission.
    exchange: u32,
    lost: bool,
    last_retransmit: Option<Instant>,
}

/// One frame selected for transmission.
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound<'a> {
    Segment { seq: u32, payload: &'a [u8] },
    Fin { seq: u32 },
}

/// Sending half: retains segments until STREAM_ACK covers them.
#[derive(Debug)]
pub struct SendStream<P> {
    next_seq: u32,
    /// Lowest sequence never dispatched; new frames go out in order.
    unsent: u32,
    cumulative: u32,
    credit_limit: u32,
    sacked: BTreeSet<u32>,
    fin: Option<u32>,
    frames: BTreeMap<u32, Outgoing<P>>,
}

impl<P: AsRef<[u8]>> Default for SendStream<P> {
    fn default() -> Self {
        SendStream {
            next_seq: 0,
            unsent: 0,
            cumulative: 0,
            credit_limit: WINDOW,
            sacked: BTreeSet::new(),
            fin: None,
            frames: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhausted;

impl<P: AsRef<[u8]>> SendStream<P> {
    fn assign(&mut self, payload: Option<P>) -> Result<u32, Exhausted> {
        assert!(self.fin.is_none(), "no data after FIN");
        let seq = self.next_seq;
        // Keep one sequence in reserve so FIN always fits.
        let limit = if payload.is_some() {
            u32::MAX - 1
        } else {
            u32::MAX
        };
        if seq >= limit {
            return Err(Exhausted);
        }
        self.next_seq += 1;
        let frame = Outgoing {
            payload,
            sent_at: None,
            transmissions: 0,
            exchange: 0,
            lost: false,
            last_retransmit: None,
        };
        self.frames.insert(seq, frame);
        Ok(seq)
    }

    pub fn push(&mut self, payload: P) -> Result<u32, Exhausted> {
        self.assign(Some(payload))
    }

    pub fn push_fin(&mut self) -> Result<u32, Exhausted> {
        let seq = self.assign(None)?;
        self.fin = Some(seq);
        Ok(seq)
    }

    pub fn fin_queued(&self) -> bool {
        self.fin.is_some()
    }

    /// Every assigned frame, FIN included, has been acknowledged.
    pub fn all_acked(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn retained(&self) -> usize {
        self.frames.len()
    }

    /// Whether anything is dispatched but not yet acknowledged.
    pub fn in_flight(&self) -> bool {
        self.frames.range(..self.unsent).next().is_some()
    }

    pub fn credit_limit(&self) -> u32 {
        self.credit_limit
    }

    /// `(cumulative, SACKed sequences, credit limit)`, as in A.7 V9.
    pub fn snapshot(&self) -> (u32, Vec<u32>, u32) {
        (
            self.cumulative,
            self.sacked.iter().copied().collect(),
            self.credit_limit,
        )
    }

    /// Merge a STREAM_ACK monotonically; SACK bits are relative to this
    /// ACK's own `next_expected`.
    pub fn apply_ack(&mut self, ack: &StreamAck, now: Instant) -> Result<AckOutcome, AckError> {
        let n = ack.next_expected;
        if n > self.unsent {
            return Err(AckError::Unsent);
        }
        let limit = n
            .checked_add(u32::from(ack.credit_delta))
            .ok_or(AckError::Overflow)?;
        let mut received = Vec::new();
        for bit in 0..32 {
            if ack.sack & (1 << bit) != 0 {
                let seq = n.checked_add(1 + bit).ok_or(AckError::Overflow)?;
                if seq >= self.unsent {
                    return Err(AckError::Unsent);
                }
                received.push(seq);
            }
        }

        let mut outcome = AckOutcome::default();
        if n > self.cumulative {
            self.cumulative = n;
            outcome.progressed = true;
        }
        if limit > self.credit_limit {
            self.credit_limit = limit;
            outcome.progressed = true;
        }
        let mut acked: Vec<u32> = self
            .frames
            .range(..self.cumulative)
            .map(|(&seq, _)| seq)
            .collect();
        acked.extend(
            received
                .iter()
                .copied()
                .filter(|seq| self.frames.contains_key(seq)),
        );
        let mut newest_sent = None;
        for seq in acked {
            let Some(frame) = self.frames.remove(&seq) else {
                continue;
            };
            outcome.progressed = true;
            if frame.payload.is_some() {
                outcome.freed_segments += 1;
            }
            if let (1, Some(sent_at)) = (frame.transmissions, frame.sent_at)
                && newest_sent.is_none_or(|newest| sent_at > newest)
            {
                newest_sent = Some(sent_at);
            }
        }
        outcome.rtt_sample = newest_sent.map(|sent_at| now.saturating_duration_since(sent_at));
        self.sacked.extend(received);
        self.sacked = self.sacked.split_off(&self.cumulative);
        Ok(outcome)
    }

    fn sendable_new(&self) -> Option<u32> {
        let seq = self.unsent;
        if seq >= self.next_seq {
            return None;
        }
        let permitted = if self.fin == Some(seq) {
            seq <= self.credit_limit
        } else {
            seq < self.credit_limit
        };
        permitted.then_some(seq)
    }

    /// The next frame to send: lost frames first (already admitted, so no
    /// credit check), then new frames within credit.
    pub fn next_frame(&self) -> Option<Outbound<'_>> {
        let seq = self
            .frames
            .iter()
            .find(|(_, frame)| frame.lost)
            .map(|(&seq, _)| seq)
            .or_else(|| self.sendable_new())?;
        Some(match &self.frames[&seq].payload {
            Some(payload) => Outbound::Segment {
                seq,
                payload: payload.as_ref(),
            },
            None => Outbound::Fin { seq },
        })
    }

    pub fn has_sendable(&self) -> bool {
        self.next_frame().is_some()
    }

    /// `seq` is queued for retransmission.
    pub fn is_retransmission(&self, seq: u32) -> bool {
        self.frames.get(&seq).is_some_and(|f| f.lost)
    }

    /// New data is waiting but credit forbids sending it.
    pub fn blocked_on_credit(&self) -> bool {
        self.unsent < self.next_seq && self.sendable_new().is_none()
    }

    /// Record dispatch of `seq` (as returned by `next_frame`) in `exchange`.
    pub fn dispatched(&mut self, seq: u32, now: Instant, exchange: u32) {
        let frame = self
            .frames
            .get_mut(&seq)
            .expect("dispatching a retained frame");
        if frame.transmissions > 0 {
            frame.last_retransmit = Some(now);
        }
        frame.transmissions += 1;
        frame.sent_at = Some(now);
        frame.exchange = exchange;
        frame.lost = false;
        if seq == self.unsent {
            self.unsent += 1;
        }
    }

    /// Exchange evidence says the copy of `seq` carried by `exchange` was
    /// lost or rejected. Ignored if a later transmission exists, and limited
    /// to one evidence-driven retransmission per sequence per RTO.
    pub fn mark_lost(&mut self, seq: u32, exchange: u32, now: Instant, rto: Duration) -> bool {
        let Some(frame) = self.frames.get_mut(&seq) else {
            return false;
        };
        let recent = frame.last_retransmit.is_some_and(|at| now < at + rto);
        if frame.lost || frame.sent_at.is_none() || frame.exchange != exchange || recent {
            return false;
        }
        frame.lost = true;
        true
    }

    /// Unacknowledged frames whose latest copy travelled in an exchange
    /// at or below `exchange`.
    pub fn carried_up_to(&self, exchange: u32) -> Vec<(u32, u32)> {
        self.frames
            .iter()
            .filter(|(_, f)| f.sent_at.is_some() && !f.lost && f.exchange <= exchange)
            .map(|(&seq, f)| (seq, f.exchange))
            .collect()
    }

    /// RTO fallback: make every timed-out frame eligible again.
    pub fn expire(&mut self, now: Instant, rto: Duration) -> bool {
        let mut any = false;
        for frame in self.frames.values_mut() {
            if let Some(sent_at) = frame.sent_at
                && !frame.lost
                && now >= sent_at + backoff(rto, frame.transmissions - 1)
            {
                frame.lost = true;
                any = true;
            }
        }
        any
    }

    pub fn next_timeout(&self, rto: Duration) -> Option<Instant> {
        self.frames
            .values()
            .filter(|f| !f.lost)
            .filter_map(|f| Some(f.sent_at? + backoff(rto, f.transmissions - 1)))
            .min()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Accepted,
    Duplicate,
    /// Beyond credit or storage: not retained and not acknowledged.
    Unadmitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// Conflicting FIN, data at or after FIN, or FIN below accepted data.
    Violation,
    /// Sequence or credit arithmetic would overflow.
    Overflow,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery<P> {
    Data(P),
    /// All bytes before FIN have been delivered.
    Fin,
}

/// Receiving half: bounded reorder buffer plus consumption-based credit.
#[derive(Debug)]
pub struct RecvStream<P> {
    next_expected: u32,
    /// First sequence not yet consumed by the bounded delivery path.
    consumed: u32,
    buffer: BTreeMap<u32, P>,
    fin: Option<u32>,
    highest_data: Option<u32>,
    highest_seen: Option<u32>,
    fin_delivered: bool,
}

impl<P> Default for RecvStream<P> {
    fn default() -> Self {
        RecvStream {
            next_expected: 0,
            consumed: 0,
            buffer: BTreeMap::new(),
            fin: None,
            highest_data: None,
            highest_seen: None,
            fin_delivered: false,
        }
    }
}

impl<P> RecvStream<P> {
    /// `max(C + 32, N)`.
    pub fn credit_limit(&self) -> Result<u32, RecvError> {
        let window = self
            .consumed
            .checked_add(WINDOW)
            .ok_or(RecvError::Overflow)?;
        Ok(window.max(self.next_expected))
    }

    fn advance(&mut self) -> Result<(), RecvError> {
        loop {
            let n = self.next_expected;
            if !self.buffer.contains_key(&n) && self.fin != Some(n) {
                return Ok(());
            }
            self.next_expected = n.checked_add(1).ok_or(RecvError::Overflow)?;
        }
    }

    fn saw(&mut self, seq: u32) {
        self.highest_seen = Some(self.highest_seen.map_or(seq, |h| h.max(seq)));
    }

    /// Admit a SEGMENT. `store` is called only for a new in-credit sequence
    /// and may refuse (returning `None`) when bounded storage is full.
    pub fn receive_segment(
        &mut self,
        seq: u32,
        store: impl FnOnce() -> Option<P>,
    ) -> Result<Admit, RecvError> {
        if self.fin.is_some_and(|fin| seq >= fin) {
            return Err(RecvError::Violation);
        }
        if seq < self.next_expected || self.buffer.contains_key(&seq) {
            return Ok(Admit::Duplicate);
        }
        if seq >= self.credit_limit()? {
            return Ok(Admit::Unadmitted);
        }
        let Some(payload) = store() else {
            return Ok(Admit::Unadmitted);
        };
        self.buffer.insert(seq, payload);
        self.highest_data = Some(self.highest_data.map_or(seq, |h| h.max(seq)));
        self.saw(seq);
        self.advance()?;
        Ok(Admit::Accepted)
    }

    /// Admit a FIN, which needs no data credit but must be at or below the
    /// credit limit.
    pub fn receive_fin(&mut self, seq: u32) -> Result<Admit, RecvError> {
        if let Some(fin) = self.fin {
            return if seq == fin {
                Ok(Admit::Duplicate)
            } else {
                Err(RecvError::Violation)
            };
        }
        if self.highest_data.is_some_and(|h| h >= seq) {
            return Err(RecvError::Violation);
        }
        if seq > self.credit_limit()? {
            return Ok(Admit::Unadmitted);
        }
        self.fin = Some(seq);
        self.saw(seq);
        self.advance()?;
        Ok(Admit::Accepted)
    }

    pub fn ack(&self, stream: u32) -> Result<StreamAck, RecvError> {
        let n = self.next_expected;
        let mut sack = 0u32;
        for bit in 0..32 {
            let Some(seq) = n.checked_add(1 + bit) else {
                break;
            };
            if self.buffer.contains_key(&seq) || self.fin == Some(seq) {
                sack |= 1 << bit;
            }
        }
        let delta = self.credit_limit()? - n;
        let credit_delta = u16::try_from(delta).map_err(|_| RecvError::Overflow)?;
        Ok(StreamAck {
            stream,
            next_expected: n,
            sack,
            credit_delta,
        })
    }

    /// Whether `deliver` would return something.
    pub fn deliverable(&self) -> bool {
        self.buffer.contains_key(&self.consumed)
            || (self.fin == Some(self.consumed) && !self.fin_delivered)
    }

    /// Hand the next contiguous item to the delivery path, advancing credit.
    pub fn deliver(&mut self) -> Option<Delivery<P>> {
        if let Some(payload) = self.buffer.remove(&self.consumed) {
            self.consumed += 1;
            return Some(Delivery::Data(payload));
        }
        if self.fin == Some(self.consumed) && !self.fin_delivered {
            self.fin_delivered = true;
            self.consumed += 1;
            return Some(Delivery::Fin);
        }
        None
    }

    pub fn fin_delivered(&self) -> bool {
        self.fin_delivered
    }

    pub fn highest_seen(&self) -> Option<u32> {
        self.highest_seen
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(n: u32, sack: u32, delta: u16) -> StreamAck {
        StreamAck {
            stream: 1,
            next_expected: n,
            sack,
            credit_delta: delta,
        }
    }

    fn tuple(r: &RecvStream<Vec<u8>>) -> (u32, u32, u16) {
        let a = r.ack(1).unwrap();
        (a.next_expected, a.sack, a.credit_delta)
    }

    fn seg(r: &mut RecvStream<Vec<u8>>, seq: u32) -> Result<Admit, RecvError> {
        r.receive_segment(seq, || Some(vec![seq as u8]))
    }

    /// A sender that has dispatched sequences `0..sent`.
    fn sender(sent: u32) -> SendStream<Vec<u8>> {
        let now = Instant::now();
        let mut s = SendStream {
            credit_limit: u32::MAX,
            ..Default::default()
        };
        for seq in 0..sent {
            s.push(vec![0]).unwrap();
            s.dispatched(seq, now, 1);
        }
        s.credit_limit = WINDOW;
        s
    }

    #[test]
    fn v5_full_window_fin() {
        let mut r = RecvStream::default();
        for seq in 0..32 {
            assert_eq!(seg(&mut r, seq), Ok(Admit::Accepted));
        }
        assert_eq!(tuple(&r), (32, 0, 0));
        assert_eq!(seg(&mut r, 32), Ok(Admit::Unadmitted));
        assert_eq!(r.receive_fin(33), Ok(Admit::Unadmitted));
        assert_eq!(r.receive_fin(32), Ok(Admit::Accepted));
        assert_eq!(tuple(&r), (33, 0, 0));
        assert_eq!((r.buffered(), r.fin_delivered()), (32, false));
        assert_eq!(r.receive_fin(32), Ok(Admit::Duplicate));
        assert_eq!(seg(&mut r, 32), Err(RecvError::Violation));
        assert_eq!(seg(&mut r, 33), Err(RecvError::Violation));
        assert_eq!(r.receive_fin(31), Err(RecvError::Violation));
        for seq in 0..32 {
            assert_eq!(r.deliver(), Some(Delivery::Data(vec![seq as u8])));
            assert!(!r.fin_delivered());
        }
        assert_eq!(r.deliver(), Some(Delivery::Fin));
        assert!(r.fin_delivered());
        assert_eq!(r.deliver(), None);

        let mut reordered = RecvStream::default();
        assert_eq!(reordered.receive_fin(32), Ok(Admit::Accepted));
        assert_eq!(tuple(&reordered), (0, 0x8000_0000, 32));
        for seq in (0..32).rev() {
            seg(&mut reordered, seq).unwrap();
        }
        assert_eq!(tuple(&reordered), (33, 0, 0));
        assert!(!reordered.fin_delivered());
    }

    #[test]
    fn fin_before_gap_and_duplicates() {
        let mut r = RecvStream::default();
        seg(&mut r, 0).unwrap();
        seg(&mut r, 2).unwrap();
        assert_eq!(r.receive_fin(3), Ok(Admit::Accepted));
        assert_eq!(tuple(&r), (1, 0b11, 31));
        assert_eq!(r.deliver(), Some(Delivery::Data(vec![0])));
        assert_eq!(r.deliver(), None, "gap at 1 blocks FIN");
        assert_eq!(seg(&mut r, 0), Ok(Admit::Duplicate));
        assert_eq!(seg(&mut r, 2), Ok(Admit::Duplicate));
        seg(&mut r, 1).unwrap();
        assert_eq!(tuple(&r), (4, 0, 29));
        assert!(matches!(r.deliver(), Some(Delivery::Data(_))));
        assert!(matches!(r.deliver(), Some(Delivery::Data(_))));
        assert_eq!(r.deliver(), Some(Delivery::Fin));
    }

    #[test]
    fn storage_refusal_is_not_acknowledged() {
        let mut r: RecvStream<Vec<u8>> = RecvStream::default();
        assert_eq!(r.receive_segment(0, || None), Ok(Admit::Unadmitted));
        assert_eq!(tuple(&r), (0, 0, 32));
    }

    #[test]
    fn credit_advances_only_on_consumption() {
        let mut r = RecvStream::default();
        for seq in 0..32 {
            seg(&mut r, seq).unwrap();
        }
        assert_eq!(tuple(&r), (32, 0, 0));
        for _ in 0..8 {
            r.deliver().unwrap();
        }
        assert_eq!(tuple(&r), (32, 0, 8));
        assert_eq!(seg(&mut r, 39), Ok(Admit::Accepted));
        assert_eq!(seg(&mut r, 40), Ok(Admit::Unadmitted));
    }

    #[test]
    fn receiver_overflow() {
        let mut r: RecvStream<Vec<u8>> = RecvStream {
            consumed: u32::MAX - 10,
            next_expected: u32::MAX - 10,
            ..Default::default()
        };
        assert_eq!(r.ack(1), Err(RecvError::Overflow));
        assert_eq!(seg(&mut r, u32::MAX - 10), Err(RecvError::Overflow));
    }

    #[test]
    fn v9_reordered_acks() {
        let now = Instant::now();
        let mut s = sender(12);
        s.apply_ack(&ack(3, 2, 29), now).unwrap();
        assert_eq!(s.snapshot(), (3, vec![5], 32));
        s.apply_ack(&ack(6, 2, 30), now).unwrap();
        assert_eq!(s.snapshot(), (6, vec![8], 36));
        s.apply_ack(&ack(3, 2, 29), now).unwrap();
        assert_eq!(s.snapshot(), (6, vec![8], 36));
        s.apply_ack(&ack(4, 0x09, 28), now).unwrap();
        assert_eq!(s.snapshot(), (6, vec![8], 36));
        assert_eq!(
            s.apply_ack(&ack(13, 0, 32), now).unwrap_err(),
            AckError::Unsent
        );
        assert_eq!(
            s.apply_ack(&ack(6, 0x20, 30), now).unwrap_err(),
            AckError::Unsent
        );
        // Frames below the cumulative ACK and SACKed frames are released.
        assert_eq!(s.retained(), 12 - 6 - 1);
    }

    #[test]
    fn ack_overflow_rejected() {
        let mut s: SendStream<Vec<u8>> = SendStream {
            unsent: u32::MAX,
            next_seq: u32::MAX,
            ..Default::default()
        };
        assert_eq!(
            s.apply_ack(&ack(u32::MAX, 0, 1), Instant::now())
                .unwrap_err(),
            AckError::Overflow
        );
    }

    #[test]
    fn v9_lost_credit_update() {
        let now = Instant::now();
        let mut s = sender(32);
        for _ in 0..10 {
            s.push(vec![1]).unwrap();
        }
        s.apply_ack(&ack(32, 0, 0), now).unwrap();
        assert!(s.blocked_on_credit());
        assert_eq!(s.next_frame(), None);

        let mut r = RecvStream::default();
        for seq in 0..32 {
            seg(&mut r, seq).unwrap();
        }
        for _ in 0..8 {
            r.deliver().unwrap();
        }
        let update = r.ack(1).unwrap();
        assert_eq!(
            (update.next_expected, update.sack, update.credit_delta),
            (32, 0, 8)
        );
        // The first update is lost; a periodic repeat repairs it.
        s.apply_ack(&update, now).unwrap();
        assert_eq!(s.credit_limit(), 40);
        for seq in 32..40 {
            assert_eq!(
                s.next_frame(),
                Some(Outbound::Segment { seq, payload: &[1] })
            );
            s.dispatched(seq, now, 2);
        }
        assert_eq!(s.next_frame(), None, "40 is blocked");
        s.apply_ack(&ack(32, 0, 0), now).unwrap();
        assert_eq!(s.credit_limit(), 40, "a late ACK never lowers credit");
    }

    #[test]
    fn fin_needs_no_credit() {
        let now = Instant::now();
        let mut s = sender(32);
        s.push_fin().unwrap();
        assert_eq!(
            s.next_frame(),
            Some(Outbound::Fin { seq: 32 }),
            "FIN at the credit limit"
        );
        s.dispatched(32, now, 2);
        s.apply_ack(&ack(33, 0, 0), now).unwrap();
        assert!(s.all_acked());
    }

    #[test]
    fn retransmission_rules() {
        let t0 = Instant::now();
        let rto = Duration::from_secs(1);
        let mut s: SendStream<Vec<u8>> = SendStream::default();
        for _ in 0..3 {
            s.push(vec![9]).unwrap();
        }
        for seq in 0..3 {
            s.dispatched(seq, t0, 10 + seq);
        }
        assert_eq!(s.next_frame(), None);
        assert_eq!(s.next_timeout(rto), Some(t0 + rto));
        // Evidence about a different exchange does not apply.
        assert!(!s.mark_lost(1, 99, t0, rto));
        assert!(s.mark_lost(1, 11, t0, rto));
        assert_eq!(
            s.next_frame(),
            Some(Outbound::Segment {
                seq: 1,
                payload: &[9]
            })
        );
        s.dispatched(1, t0, 20);
        // At most one evidence-driven retransmission per RTO.
        assert!(!s.mark_lost(1, 20, t0 + rto / 2, rto));
        assert!(s.mark_lost(1, 20, t0 + rto, rto));
        s.dispatched(1, t0 + rto, 21);
        // Timeout recovery with exponential backoff.
        assert!(s.expire(t0 + rto, rto));
        assert_eq!(s.carried_up_to(100), vec![(1, 21)]);
        s.dispatched(0, t0 + rto, 22);
        s.dispatched(2, t0 + rto, 22);
        assert_eq!(s.next_timeout(rto), Some(t0 + rto * 3));
        // Retransmitted frames do not produce RTT samples.
        let out = s.apply_ack(&ack(3, 0, 32), t0 + rto * 2).unwrap();
        assert_eq!((out.freed_segments, out.rtt_sample), (3, None));
    }

    #[test]
    fn rtt_estimator() {
        let mut rtt = Rtt::default();
        assert_eq!(rtt.rto(), INITIAL_RTO);
        rtt.sample(Duration::from_millis(10));
        assert_eq!(rtt.rto(), MIN_RTO);
        for _ in 0..50 {
            rtt.sample(Duration::from_secs(9));
        }
        assert_eq!(rtt.rto(), MAX_RTO);
        assert_eq!(backoff(Duration::from_secs(1), 10), MAX_RTO);
    }

    #[test]
    fn sequence_exhaustion() {
        let mut s: SendStream<Vec<u8>> = SendStream {
            next_seq: u32::MAX - 1,
            unsent: u32::MAX - 1,
            ..Default::default()
        };
        assert_eq!(s.push(vec![1]), Err(Exhausted));
        assert_eq!(s.push_fin(), Ok(u32::MAX - 1));
    }
}
