//! Server-initiated streams. The high bit separates these IDs from forward
//! streams; OPEN travels server -> client and OPEN_RESULT travels back.

use std::collections::{BTreeMap, HashMap};
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::server::{Action, IdCheck, StreamIds};
use super::{
    Budget, Chunk, HasPipe, IoEvent, IoKind, MAX_STREAMS, OPEN_DEADLINE, Packer, Pipe,
    ResetRepeats, Tombstone, Tombstones, WriteCmd, pack_acks, pack_data,
};
use crate::arq::{Admit, Delivery};
use crate::wire::{Frame, MAX_OPEN_RECORD, OpenResult, StreamAck, reset, status};

pub(super) const FIRST_ID: u32 = 0x8000_0000;
pub(super) const KEY_BIT: u64 = 1 << 63;

pub(super) fn is_reverse(frame: &Frame) -> bool {
    let id = match frame {
        Frame::Segment { stream, .. } | Frame::Fin { stream, .. } | Frame::Reset { stream, .. } => {
            *stream
        }
        Frame::StreamAck(ack) => ack.stream,
        _ => return false,
    };
    id >= FIRST_ID
}

#[derive(Debug)]
enum Phase {
    Reply(Vec<u8>),
    Open(Vec<u8>),
    Dialing(Vec<u8>),
    Connected,
    Failed,
}

struct Stream {
    pipe: Pipe,
    key: u64,
    phase: Phase,
    deadline: Instant,
}

impl HasPipe for Stream {
    fn pipe(&mut self) -> &mut Pipe {
        &mut self.pipe
    }
}

pub(super) struct Streams {
    opener: bool,
    streams: BTreeMap<u32, Stream>,
    keys: HashMap<u64, u32>,
    key_source: Arc<AtomicU64>,
    next_id: u32,
    ids: StreamIds,
    tombstones: Tombstones,
    late_acks: Vec<StreamAck>,
    resets: ResetRepeats,
    cursor: u32,
    send_size: usize,
    recv_size: usize,
    budget: Budget,
    actions: Vec<Action>,
}

impl Streams {
    pub(super) fn new(
        opener: bool,
        send_size: usize,
        recv_size: usize,
        budget: Budget,
        key_source: Arc<AtomicU64>,
    ) -> Self {
        Self {
            opener,
            streams: BTreeMap::new(),
            keys: HashMap::new(),
            key_source,
            next_id: FIRST_ID,
            ids: StreamIds::default(),
            tombstones: Tombstones::default(),
            late_acks: Vec::new(),
            resets: ResetRepeats::default(),
            cursor: 0,
            send_size,
            recv_size,
            budget,
            actions: Vec::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.streams.len()
    }

    pub(super) fn open(&mut self, event: IoEvent, now: Instant, available: usize) {
        let IoKind::Open {
            target,
            writer,
            permits,
        } = event.kind
        else {
            return;
        };
        if !self.opener || available == 0 || self.next_id == u32::MAX {
            let _ = writer.try_send(WriteCmd::Reply(OpenResult::failure(status::FAILURE)));
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut pipe = Pipe::new(now, self.recv_size);
        pipe.writer = Some(writer);
        pipe.permits = Some(permits);
        let used = pipe.push_record(&target.encode(), self.send_size);
        pipe.grant_initial_permits(used);
        self.keys.insert(event.key, id);
        self.streams.insert(
            id,
            Stream {
                pipe,
                key: event.key,
                phase: Phase::Reply(Vec::new()),
                deadline: now + OPEN_DEADLINE,
            },
        );
    }

    fn remove(&mut self, id: u32) -> Option<Stream> {
        let stream = self.streams.remove(&id)?;
        self.keys.remove(&stream.key);
        Some(stream)
    }

    fn abort(&mut self, id: u32, reason: u8, now: Instant) {
        self.remove(id);
        self.tombstones.insert(id, Tombstone::Reset(reason), now);
        self.resets.push(id, reason, now);
    }

    pub(super) fn apply(&mut self, frame: Frame, now: Instant, available: usize) -> bool {
        match frame {
            Frame::StreamAck(ack) => {
                if let Some(stream) = self.streams.get_mut(&ack.stream)
                    && stream.pipe.on_ack(&ack, now).is_err()
                {
                    self.abort(ack.stream, reset::PROTOCOL, now);
                }
                self.drive(ack.stream, now);
                false
            }
            Frame::Reset { stream, .. } => {
                if self.remove(stream).is_some() {
                    self.tombstones
                        .insert(stream, Tombstone::Reset(reset::UNKNOWN_STREAM), now);
                }
                false
            }
            Frame::Segment {
                stream,
                seq,
                payload,
            } => self.receive(stream, seq, Some(&payload), now, available),
            Frame::Fin { stream, seq } => self.receive(stream, seq, None, now, available),
            _ => false,
        }
    }

    fn receive(
        &mut self,
        id: u32,
        seq: u32,
        payload: Option<&[u8]>,
        now: Instant,
        available: usize,
    ) -> bool {
        if !self.streams.contains_key(&id) {
            match self.tombstones.get(id, now) {
                Some(Tombstone::Closed(ack)) => {
                    if !self.late_acks.contains(&ack) {
                        self.late_acks.push(ack);
                    }
                    return false;
                }
                Some(Tombstone::Reset(reason)) => {
                    self.resets.push(id, reason, now);
                    return false;
                }
                None => {}
            }
            if self.opener || self.ids.check(id) != IdCheck::Fresh {
                self.resets.push(id, reset::UNKNOWN_STREAM, now);
                return false;
            }
            if available == 0 || self.streams.len() >= MAX_STREAMS {
                self.resets.push(id, reset::RESOURCE, now);
                return false;
            }
            let key = KEY_BIT | self.key_source.fetch_add(1, Ordering::Relaxed);
            self.keys.insert(key, id);
            self.streams.insert(
                id,
                Stream {
                    pipe: Pipe::new(now, self.recv_size),
                    key,
                    phase: Phase::Open(Vec::new()),
                    deadline: now + OPEN_DEADLINE,
                },
            );
        }
        let stream = self.streams.get_mut(&id).expect("present");
        let result = match payload {
            Some(bytes) => stream.pipe.on_segment(seq, bytes, &self.budget),
            None => stream.pipe.on_fin(seq),
        };
        match result {
            Ok(admit) => {
                self.drive(id, now);
                admit == Admit::Accepted
            }
            Err(_) => {
                self.abort(id, reset::PROTOCOL, now);
                false
            }
        }
    }

    fn drive(&mut self, id: u32, now: Instant) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let mut next = None;
        let mut abort = false;
        match &mut stream.phase {
            Phase::Open(buf) | Phase::Reply(buf) => {
                let opener = self.opener;
                while let Some(item) = stream.pipe.take_one(now) {
                    let Delivery::Data(chunk) = item else {
                        abort = true;
                        break;
                    };
                    buf.extend_from_slice(chunk.as_ref());
                    if opener {
                        match OpenResult::parse(buf) {
                            Err(_) => {
                                abort = true;
                                break;
                            }
                            Ok(None) => {}
                            Ok(Some((result, used))) => {
                                let writer = stream.pipe.writer.take().expect("SOCKS writer");
                                let _ = writer.try_send(WriteCmd::Reply(result));
                                if result.status == status::SUCCEEDED {
                                    if used < buf.len() {
                                        let _ = writer.try_send(WriteCmd::Data(Chunk::new(
                                            buf[used..].to_vec(),
                                        )));
                                    }
                                    stream.pipe.writer = Some(writer);
                                    next = Some(Phase::Connected);
                                } else {
                                    stream.pipe.push_fin();
                                    next = Some(Phase::Failed);
                                }
                                break;
                            }
                        }
                    } else {
                        match crate::wire::Target::parse(buf) {
                            Err(_) => {
                                abort = true;
                                break;
                            }
                            Ok(None) => {}
                            Ok(Some((target, used))) => {
                                self.actions.push(Action::Dial {
                                    key: stream.key,
                                    target,
                                    deadline: stream.deadline,
                                });
                                next = Some(Phase::Dialing(buf[used..].to_vec()));
                                break;
                            }
                        }
                    }
                    if buf.len() > MAX_OPEN_RECORD {
                        abort = true;
                        break;
                    }
                }
            }
            Phase::Failed => while stream.pipe.take_one(now).is_some() {},
            _ => {}
        }
        if let Some(phase) = next {
            stream.phase = phase;
        }
        if matches!(stream.phase, Phase::Connected) {
            stream.pipe.deliver_to_writer(now);
        }
        if abort {
            self.abort(id, reset::PROTOCOL, now);
        } else if stream.pipe.finished() {
            if let Ok(ack) = stream.pipe.ack(id) {
                self.tombstones.insert(id, Tombstone::Closed(ack), now);
            }
            self.remove(id);
        }
    }

    pub(super) fn handle_io(&mut self, event: IoEvent, now: Instant) {
        let Some(&id) = self.keys.get(&event.key) else {
            return;
        };
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        match event.kind {
            IoKind::Connected {
                writer,
                permits,
                local,
            } => {
                let Phase::Dialing(early) = &mut stream.phase else {
                    return;
                };
                let early = mem::take(early);
                stream.pipe.permits = Some(permits);
                let record = OpenResult {
                    status: status::SUCCEEDED,
                    bound: local,
                }
                .encode();
                let used = stream.pipe.push_record(&record, self.send_size);
                stream.pipe.grant_initial_permits(used);
                if !early.is_empty() {
                    let _ = writer.try_send(WriteCmd::Data(Chunk::new(early)));
                }
                stream.pipe.writer = Some(writer);
                stream.phase = Phase::Connected;
            }
            IoKind::DialFailed(code) => {
                if !matches!(stream.phase, Phase::Dialing(_)) {
                    return;
                }
                stream
                    .pipe
                    .push_record(&OpenResult::failure(code).encode(), self.send_size);
                stream.pipe.push_fin();
                stream.phase = Phase::Failed;
            }
            IoKind::Data(chunk) => {
                if !stream.pipe.push_data(chunk) {
                    return self.abort(id, reset::EXHAUSTED, now);
                }
            }
            IoKind::Eof => {
                if !stream.pipe.push_fin() {
                    return self.abort(id, reset::EXHAUSTED, now);
                }
            }
            IoKind::ReadError | IoKind::WriteError | IoKind::Closed => {
                return self.abort(id, reset::LOCAL_ABORT, now);
            }
            _ => {}
        }
        self.drive(id, now);
    }

    pub(super) fn pending(&self, now: Instant) -> bool {
        self.resets.due(now)
            || !self.late_acks.is_empty()
            || self
                .streams
                .values()
                .any(|s| s.pipe.send.has_sendable() || s.pipe.ack_dirty)
    }

    pub(super) fn mandatory_ack(&mut self, id: u32, now: Instant) -> Option<Frame> {
        if let Some(stream) = self.streams.get_mut(&id) {
            match stream.pipe.ack(id) {
                Ok(ack) => {
                    stream.pipe.ack_dirty = false;
                    return Some(Frame::StreamAck(ack));
                }
                Err(_) => self.abort(id, reset::EXHAUSTED, now),
            }
        }
        self.tombstones
            .get(id, now)
            .map(|tombstone| match tombstone {
                Tombstone::Closed(ack) => Frame::StreamAck(ack),
                Tombstone::Reset(reason) => Frame::Reset { stream: id, reason },
            })
    }

    pub(super) fn pack_acks(&mut self, packer: &mut Packer, now: Instant, limit: usize) {
        self.resets.pack(packer, now);
        while let Some(ack) = self.late_acks.pop() {
            if !packer.push(Frame::StreamAck(ack)) {
                self.late_acks.push(ack);
                break;
            }
        }
        for id in pack_acks(&mut self.streams, packer, limit) {
            self.abort(id, reset::EXHAUSTED, now);
        }
    }

    pub(super) fn pack_data(
        &mut self,
        packer: &mut Packer,
        exchange: u32,
        max_streams: usize,
        now: Instant,
    ) -> Vec<(u32, u32)> {
        pack_data(
            &mut self.streams,
            &mut self.cursor,
            packer,
            exchange,
            max_streams,
            now,
        )
    }

    pub(super) fn mark_lost(
        &mut self,
        id: u32,
        seq: u32,
        exchange: u32,
        now: Instant,
        rto: Duration,
    ) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.pipe.send.mark_lost(seq, exchange, now, rto);
        }
    }

    pub(super) fn timers(&mut self, now: Instant, rto: Duration, evidence: Option<u32>) {
        let mut aborts = Vec::new();
        for (&id, stream) in &mut self.streams {
            if let Some(limit) = evidence {
                for (seq, exchange) in stream.pipe.send.carried_up_to(limit) {
                    stream.pipe.send.mark_lost(seq, exchange, now, rto);
                }
            }
            stream.pipe.send.expire(now, rto);
            stream.pipe.credit_repeat_due(now);
            if stream.pipe.stalled(now) {
                aborts.push((id, reset::STALLED));
            } else if matches!(
                stream.phase,
                Phase::Open(_) | Phase::Reply(_) | Phase::Dialing(_)
            ) && now >= stream.deadline
            {
                if self.opener
                    && let Some(writer) = &stream.pipe.writer
                {
                    let _ =
                        writer.try_send(WriteCmd::Reply(OpenResult::failure(status::TIMED_OUT)));
                }
                aborts.push((id, reset::OPEN_DEADLINE));
            }
        }
        for (id, reason) in aborts {
            self.abort(id, reason, now);
        }
        self.tombstones.prune(now);
    }

    pub(super) fn next_deadline(&self, now: Instant, rto: Duration) -> Option<Instant> {
        self.streams
            .values()
            .filter_map(|s| s.pipe.next_deadline(rto))
            .chain(self.resets.next_deadline(now))
            .min()
    }

    pub(super) fn take_actions(&mut self) -> Vec<Action> {
        // An OPEN can be reset or expire before the driver drains its action.
        mem::take(&mut self.actions)
            .into_iter()
            .filter(|action| {
                let Action::Dial { key, .. } = action;
                self.keys.contains_key(key)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::WRITE_QUEUE;
    use crate::wire::{Host, Target};
    use tokio::sync::{Semaphore, mpsc};

    fn streams(opener: bool) -> Streams {
        Streams::new(
            opener,
            100,
            100,
            Budget::new(1 << 20),
            Arc::new(AtomicU64::new(1)),
        )
    }

    fn open(streams: &mut Streams, now: Instant, available: usize) -> mpsc::Receiver<WriteCmd> {
        let (writer, writes) = mpsc::channel(WRITE_QUEUE);
        streams.open(
            IoEvent {
                key: KEY_BIT,
                kind: IoKind::Open {
                    target: Target {
                        host: Host::Ip("127.0.0.1".parse().unwrap()),
                        port: 80,
                    },
                    writer,
                    permits: Arc::new(Semaphore::new(0)),
                },
            },
            now,
            available,
        );
        writes
    }

    #[test]
    fn final_ack_releases_stream_and_late_fin_is_acked() {
        let now = Instant::now();
        let mut s = streams(true);
        let mut writes = open(&mut s, now, 1);
        let mut p = Packer::new(1000);
        s.pack_data(&mut p, 1, 1, now); // OPEN seq 0.
        s.handle_io(
            IoEvent {
                key: KEY_BIT,
                kind: IoKind::Eof,
            },
            now,
        );
        s.pack_data(&mut p, 2, 1, now); // FIN seq 1.
        let result = OpenResult {
            status: status::SUCCEEDED,
            bound: "127.0.0.1:9000".parse().unwrap(),
        };
        s.apply(
            Frame::Segment {
                stream: FIRST_ID,
                seq: 0,
                payload: result.encode(),
            },
            now,
            0,
        );
        s.apply(
            Frame::Fin {
                stream: FIRST_ID,
                seq: 1,
            },
            now,
            0,
        );
        assert_eq!(s.len(), 1);
        s.apply(
            Frame::StreamAck(StreamAck {
                stream: FIRST_ID,
                next_expected: 2,
                sack: 0,
                credit_delta: 32,
            }),
            now,
            0,
        );
        assert_eq!(
            s.len(),
            0,
            "last ACK must release a gracefully closed stream"
        );
        assert!(matches!(writes.try_recv(), Ok(WriteCmd::Reply(_))));
        assert!(matches!(writes.try_recv(), Ok(WriteCmd::Shutdown)));
        assert!(matches!(
            writes.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        s.apply(
            Frame::Fin {
                stream: FIRST_ID,
                seq: 1,
            },
            now,
            0,
        );
        let mut p = Packer::new(100);
        s.pack_acks(&mut p, now, 4);
        assert!(matches!(p.into_frames().as_slice(), [Frame::StreamAck(_)]));
    }

    #[test]
    fn opening_deadline_and_resource_limit_fail_socks_requests() {
        let now = Instant::now();
        let mut s = streams(true);
        let mut rejected = open(&mut s, now, 0);
        assert!(
            matches!(rejected.try_recv(), Ok(WriteCmd::Reply(r)) if r.status == status::FAILURE)
        );
        assert_eq!(s.len(), 0);
        let mut expired = open(&mut s, now, 1);
        s.timers(now + OPEN_DEADLINE, Duration::from_secs(1), None);
        assert_eq!(s.len(), 0);
        assert!(
            matches!(expired.try_recv(), Ok(WriteCmd::Reply(r)) if r.status == status::TIMED_OUT)
        );
    }

    #[test]
    fn reordered_open_dials_once_and_reset_cancels_pending_action() {
        let now = Instant::now();
        let mut s = streams(false);
        let target = Target {
            host: Host::Domain("example.org".into()),
            port: 443,
        }
        .encode();
        let second = Frame::Segment {
            stream: FIRST_ID,
            seq: 1,
            payload: target[3..].to_vec(),
        };
        s.apply(second.clone(), now, 1);
        assert!(s.take_actions().is_empty());
        s.apply(
            Frame::Segment {
                stream: FIRST_ID,
                seq: 0,
                payload: target[..3].to_vec(),
            },
            now,
            0,
        );
        s.apply(second, now, 0);
        assert_eq!(s.actions.len(), 1);
        s.apply(
            Frame::Reset {
                stream: FIRST_ID,
                reason: reset::LOCAL_ABORT,
            },
            now,
            0,
        );
        assert!(s.take_actions().is_empty());
        s.tombstones.clear();
        s.apply(
            Frame::Segment {
                stream: FIRST_ID,
                seq: 0,
                payload: target,
            },
            now,
            1,
        );
        assert_eq!(
            s.len(),
            0,
            "a used ID cannot reopen after its tombstone expires"
        );
        assert!(s.take_actions().is_empty());
    }
}
