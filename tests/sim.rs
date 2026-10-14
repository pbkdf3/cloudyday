//! Deterministic client/server simulation over a lossy, duplicating,
//! reordering network with simulated time. No sockets or real clocks.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloudyday::dns::TunnelDomain;
use cloudyday::session::client::ClientCore;
use cloudyday::session::server::{Action, BUFFER_LIMIT, ServerCore};
use cloudyday::session::{Budget, Chunk, IoEvent, IoKind, WRITE_QUEUE, WriteCmd};
use cloudyday::wire::{Host, OpenResult, Target, XorKey, status};
use tokio::sync::{Semaphore, mpsc};

const UNIX_BASE: u64 = 1_700_000_000;
const STEP: Duration = Duration::from_millis(1);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn chance(&mut self, p: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 1_000_000.0 < p
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

#[derive(Clone, Copy)]
struct Faults {
    loss: f64,
    dup: f64,
    max_delay_ms: u64,
    base_delay_ms: u64,
}

const CLEAN: Faults = Faults {
    loss: 0.0,
    dup: 0.0,
    max_delay_ms: 0,
    base_delay_ms: 20,
};

#[derive(Clone, Copy)]
enum Dir {
    ToServer,
    ToClient,
}

/// Fake SOCKS application: sends `upload`, records what comes back.
struct App {
    key: u64,
    writes: mpsc::Receiver<WriteCmd>,
    permits: Arc<Semaphore>,
    upload: VecDeque<u8>,
    sent_eof: bool,
    received: Vec<u8>,
    reply: Option<OpenResult>,
    shutdown: bool,
    closed: bool,
}

/// Fake destination: echoes everything, then closes after the client does.
struct Dest {
    key: u64,
    writes: mpsc::Receiver<WriteCmd>,
    permits: Arc<Semaphore>,
    echo: VecDeque<u8>,
    shutdown: bool,
    sent_eof: bool,
}

struct Sim {
    client: ClientCore,
    server: ServerCore,
    rng: Rng,
    faults: Faults,
    t0: Instant,
    now: Instant,
    wire: Vec<(Instant, Dir, Vec<u8>)>,
    apps: Vec<App>,
    dests: Vec<Dest>,
    dials: usize,
    next_key: u64,
    queries: usize,
    /// Bytes each new destination sends unprompted (download source).
    dest_prefill: usize,
    u: usize,
    d: usize,
}

fn domain() -> TunnelDomain {
    TunnelDomain::parse("t.example.com").unwrap()
}

fn key() -> XorKey {
    XorKey::new(b"simulation key".to_vec()).unwrap()
}

impl Sim {
    fn new(faults: Faults, seed: u64) -> Sim {
        let client = ClientCore::new(domain(), key()).unwrap();
        let sizes = client.sizes();
        let now = Instant::now();
        Sim {
            client,
            server: ServerCore::new(domain(), key(), Budget::new(BUFFER_LIMIT)).unwrap(),
            rng: Rng(seed),
            faults,
            t0: now,
            now,
            wire: Vec::new(),
            apps: Vec::new(),
            dests: Vec::new(),
            dials: 0,
            next_key: 1,
            queries: 0,
            dest_prefill: 0,
            u: sizes.u,
            d: sizes.d,
        }
    }

    fn open(&mut self, upload: Vec<u8>) -> usize {
        let (writer, writes) = mpsc::channel(WRITE_QUEUE);
        let permits = Arc::new(Semaphore::new(0));
        let key = self.next_key;
        self.next_key += 1;
        let target = Target {
            host: Host::Ip("203.0.113.7".parse().unwrap()),
            port: 7,
        };
        self.client.handle_io(
            IoEvent {
                key,
                kind: IoKind::Open {
                    target,
                    writer,
                    permits: permits.clone(),
                },
            },
            self.now,
        );
        self.apps.push(App {
            key,
            writes,
            permits,
            upload: upload.into(),
            sent_eof: false,
            received: Vec::new(),
            reply: None,
            shutdown: false,
            closed: false,
        });
        self.apps.len() - 1
    }

    fn transmit(&mut self, dir: Dir, packet: Vec<u8>) {
        let f = self.faults;
        if self.rng.chance(f.loss) {
            return;
        }
        let copies = if self.rng.chance(f.dup) { 2 } else { 1 };
        for _ in 0..copies {
            let delay = f.base_delay_ms + self.rng.below(f.max_delay_ms + 1);
            let at = self.now + Duration::from_millis(delay);
            self.wire.push((at, dir, packet.clone()));
        }
    }

    fn step(&mut self) {
        let resolver: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let unix = UNIX_BASE + (self.now - self.t0).as_secs();
        for query in self.client.poll(self.now) {
            self.queries += 1;
            self.transmit(Dir::ToServer, query);
        }
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.wire)
            .into_iter()
            .partition(|(at, ..)| *at <= self.now);
        self.wire = later;
        for (_, dir, packet) in due {
            match dir {
                Dir::ToServer => {
                    if let Some(response) = self
                        .server
                        .handle_datagram(resolver, &packet, self.now, unix)
                    {
                        self.transmit(Dir::ToClient, response);
                    }
                }
                Dir::ToClient => self.client.handle_datagram(&packet, self.now),
            }
        }
        for action in self.server.take_actions() {
            let Action::Dial { key, .. } = action;
            self.dials += 1;
            let (writer, writes) = mpsc::channel(WRITE_QUEUE);
            let permits = Arc::new(Semaphore::new(0));
            let local = "198.51.100.1:5000".parse().unwrap();
            self.server.handle_io(
                IoEvent {
                    key,
                    kind: IoKind::Connected {
                        writer,
                        permits: permits.clone(),
                        local,
                    },
                },
                self.now,
            );
            let echo = payload(self.dest_prefill, 0).into();
            self.dests.push(Dest {
                key,
                writes,
                permits,
                echo,
                shutdown: false,
                sent_eof: false,
            });
        }
        self.run_apps();
        self.run_dests();
        if (self.now - self.t0).as_millis() % 1000 < STEP.as_millis() {
            self.server.housekeeping(self.now, unix);
        }
        self.now += STEP;
    }

    fn run_apps(&mut self) {
        for app in &mut self.apps {
            if app.closed {
                continue;
            }
            loop {
                match app.writes.try_recv() {
                    Ok(WriteCmd::Reply(result)) => app.reply = Some(result),
                    Ok(WriteCmd::Data(chunk)) => {
                        app.received.extend_from_slice(chunk.as_ref());
                        self.client.handle_io(
                            IoEvent {
                                key: app.key,
                                kind: IoKind::Written,
                            },
                            self.now,
                        );
                    }
                    Ok(WriteCmd::Shutdown) => app.shutdown = true,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        app.closed = true;
                        break;
                    }
                }
            }
            if app.reply.is_none_or(|r| r.status != status::SUCCEEDED) {
                continue;
            }
            while !app.upload.is_empty()
                && app.permits.try_acquire().is_ok_and(|p| {
                    p.forget();
                    true
                })
            {
                let n = app.upload.len().min(self.u);
                let chunk: Vec<u8> = app.upload.drain(..n).collect();
                self.client.handle_io(
                    IoEvent {
                        key: app.key,
                        kind: IoKind::Data(Chunk::new(chunk)),
                    },
                    self.now,
                );
            }
            if app.upload.is_empty() && !app.sent_eof {
                app.sent_eof = true;
                self.client.handle_io(
                    IoEvent {
                        key: app.key,
                        kind: IoKind::Eof,
                    },
                    self.now,
                );
            }
        }
    }

    fn run_dests(&mut self) {
        for dest in &mut self.dests {
            while let Ok(command) = dest.writes.try_recv() {
                match command {
                    WriteCmd::Data(chunk) => {
                        dest.echo.extend(chunk.as_ref());
                        self.server.handle_io(
                            IoEvent {
                                key: dest.key,
                                kind: IoKind::Written,
                            },
                            self.now,
                        );
                    }
                    WriteCmd::Shutdown => dest.shutdown = true,
                    WriteCmd::Reply(_) => {}
                }
            }
            while !dest.echo.is_empty()
                && dest.permits.try_acquire().is_ok_and(|p| {
                    p.forget();
                    true
                })
            {
                let n = dest.echo.len().min(self.d);
                let chunk: Vec<u8> = dest.echo.drain(..n).collect();
                self.server.handle_io(
                    IoEvent {
                        key: dest.key,
                        kind: IoKind::Data(Chunk::new(chunk)),
                    },
                    self.now,
                );
            }
            if dest.shutdown && dest.echo.is_empty() && !dest.sent_eof {
                dest.sent_eof = true;
                self.server.handle_io(
                    IoEvent {
                        key: dest.key,
                        kind: IoKind::Eof,
                    },
                    self.now,
                );
            }
        }
    }

    fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&Sim) -> bool) -> Duration {
        while !done(self) {
            assert!(
                self.now - self.t0 < limit,
                "simulation did not finish within {limit:?}"
            );
            self.step();
        }
        self.now - self.t0
    }
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Every app got its upload echoed back exactly, then a clean shutdown,
/// and the client released the connection.
fn all_echoed(sim: &Sim, uploads: &[Vec<u8>]) -> bool {
    sim.apps
        .iter()
        .zip(uploads)
        .all(|(app, sent)| app.received == *sent && app.shutdown && app.closed)
}

fn echo_test(faults: Faults, seed: u64, sizes: &[usize], limit: Duration) -> Sim {
    let mut sim = Sim::new(faults, seed);
    let uploads: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| payload(n, i as u8))
        .collect();
    for upload in &uploads {
        sim.open(upload.clone());
    }
    let elapsed = sim.run_until(limit, |sim| all_echoed(sim, &uploads));
    for app in &sim.apps {
        assert_eq!(app.reply.unwrap().status, status::SUCCEEDED);
    }
    assert_eq!(
        sim.dials,
        sizes.len(),
        "exactly one destination connection per stream"
    );
    eprintln!("finished in {elapsed:?} with {} queries", sim.queries);
    sim
}

#[test]
fn clean_network_round_trip() {
    echo_test(CLEAN, 1, &[1, 20_000, 0, 5_000], Duration::from_secs(60));
}

#[test]
fn lossy_duplicating_reordering_network() {
    let faults = Faults {
        loss: 0.15,
        dup: 0.10,
        max_delay_ms: 120,
        base_delay_ms: 20,
    };
    for seed in [7, 99, 12345] {
        echo_test(
            faults,
            seed,
            &[30_000, 4_000, 12_000],
            Duration::from_secs(600),
        );
    }
}

#[test]
fn heavy_loss_still_delivers_exactly() {
    let faults = Faults {
        loss: 0.35,
        dup: 0.05,
        max_delay_ms: 300,
        base_delay_ms: 50,
    };
    echo_test(faults, 4242, &[8_000, 8_000], Duration::from_secs(900));
}

#[test]
fn many_concurrent_streams() {
    let faults = Faults {
        loss: 0.05,
        dup: 0.02,
        max_delay_ms: 50,
        base_delay_ms: 20,
    };
    let sizes: Vec<usize> = (0..40).map(|i| 500 + i * 97).collect();
    echo_test(faults, 31337, &sizes, Duration::from_secs(600));
}

#[test]
fn server_restart_fails_streams_then_recovers() {
    let mut sim = Sim::new(CLEAN, 5);
    // A long upload keeps the first stream busy.
    sim.open(payload(200_000, 1));
    sim.run_until(Duration::from_secs(60), |sim| {
        sim.apps[0].received.len() > 10_000
    });
    let old_session = sim.client.established().unwrap();
    sim.server = ServerCore::new(domain(), key(), Budget::new(BUFFER_LIMIT)).unwrap();
    // The client learns of the loss from SESSION_ERROR and fails the stream
    // promptly, without replaying bytes into a new destination connection.
    let elapsed = sim.run_until(Duration::from_secs(70), |sim| sim.apps[0].closed);
    assert!(elapsed < Duration::from_secs(70));
    assert!(sim.apps[0].received.len() < 200_000);
    assert_eq!(sim.dials, 1);
    // A new connection establishes a new session.
    let upload = payload(3_000, 9);
    sim.open(upload.clone());
    sim.run_until(Duration::from_secs(140), |sim| {
        sim.apps[1].received == upload && sim.apps[1].closed
    });
    assert_ne!(sim.client.established(), Some(old_session));
    assert_eq!(sim.dials, 2);
}

#[test]
fn slow_reader_bounds_buffering() {
    // The destination never reads: the client must stop at the windows,
    // with the server holding a bounded amount of data.
    let mut sim = Sim::new(CLEAN, 11);
    sim.open(payload(500_000, 3));
    sim.run_until(Duration::from_secs(60), |sim| !sim.dests.is_empty());
    let dest = sim.dests.pop().unwrap();
    let start = sim.now;
    while sim.now - start < Duration::from_secs(20) {
        sim.step();
    }
    let app = &sim.apps[0];
    let uploaded = 500_000 - app.upload.len();
    // OPEN record + 32-frame receive window + 8 queued writes + 32 in flight.
    let bound = (1 + 32 + 8 + 32) * sim.u;
    assert!(
        uploaded <= bound,
        "uploaded {uploaded} bytes past a stalled reader (bound {bound})"
    );
    drop(dest);
}

/// One-way throughput on a clean 40 ms round trip. Run with
/// `cargo test --release --test sim -- --ignored --nocapture`.
#[test]
#[ignore]
fn measure_throughput() {
    for (label, up, down) in [("upload", 200_000, 0), ("download", 0, 200_000)] {
        let mut sim = Sim::new(CLEAN, 3);
        sim.dest_prefill = down;
        sim.open(payload(up, 1));
        let mut samples = Vec::new();
        let elapsed = sim.run_until(Duration::from_secs(600), |sim| {
            if (sim.now - sim.t0).as_millis() % 250 == 0 {
                samples.push(sim.client.pipeline());
            }
            sim.apps[0].received.len() == up + down && sim.apps[0].shutdown
        });
        eprintln!("{label} (depth, in flight) every 250 ms: {samples:?}");
        let rate = (up + down) as f64 / elapsed.as_secs_f64() / 1000.0;
        eprintln!(
            "{label}: {:.1} KB/s, {} queries, {:?}",
            rate, sim.queries, elapsed
        );
    }
}
