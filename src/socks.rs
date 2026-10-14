//! SOCKS5 CONNECT negotiation and TCP bridging (A.5).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tracing::debug;

use crate::session::{Budget, Chunk, IoEvent, IoKind, WRITE_QUEUE, WriteCmd};
use crate::wire::{Host, OpenResult, Target, status, valid_hostname};

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const UNSPECIFIED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Serve one SOCKS connection: negotiate, ask the session for a stream,
/// relay its OPEN_RESULT as the reply, then bridge.
pub async fn serve(mut tcp: TcpStream, key: u64, events: mpsc::Sender<IoEvent>, segment: usize) {
    let target = match tokio::time::timeout(NEGOTIATION_TIMEOUT, negotiate(&mut tcp)).await {
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => return debug!(%e, "SOCKS negotiation failed"),
        Err(_) => return debug!("SOCKS negotiation timed out"),
    };
    let (writer, mut writes) = mpsc::channel(WRITE_QUEUE);
    let permits = Arc::new(Semaphore::new(0));
    let open = IoKind::Open {
        target,
        writer,
        permits: permits.clone(),
    };
    if events.send(IoEvent { key, kind: open }).await.is_err() {
        return;
    }

    // Wait for the reply, noticing if the application gives up first.
    let mut watching = true;
    let reply = loop {
        let mut probe = [0u8; 1];
        tokio::select! {
            command = writes.recv() => break command,
            peeked = tcp.peek(&mut probe), if watching => match peeked {
                Ok(0) | Err(_) => {
                    let _ = events.send(IoEvent { key, kind: IoKind::Closed }).await;
                    return;
                }
                // Early application bytes stay queued until after the reply.
                Ok(_) => watching = false,
            },
        }
    };
    let result = match reply {
        Some(WriteCmd::Reply(result)) => result,
        _ => OpenResult::failure(status::FAILURE),
    };
    if write_reply(&mut tcp, result.status, result.bound)
        .await
        .is_err()
    {
        let _ = events
            .send(IoEvent {
                key,
                kind: IoKind::ReadError,
            })
            .await;
        return;
    }
    if result.status == status::SUCCEEDED {
        bridge(
            tcp,
            key,
            segment,
            events,
            permits,
            writes,
            Budget::unlimited(),
        )
        .await;
    }
}

async fn negotiate(tcp: &mut TcpStream) -> io::Result<Option<Target>> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(bad("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        tcp.write_all(&[5, NO_ACCEPTABLE_METHODS]).await?;
        return Ok(None);
    }
    tcp.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    tcp.read_exact(&mut request).await?;
    if request[0] != 5 {
        return Err(bad("not SOCKS5"));
    }
    let host = match request[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            tcp.read_exact(&mut ip).await?;
            Host::Ip(Ipv4Addr::from(ip).into())
        }
        0x04 => {
            let mut ip = [0u8; 16];
            tcp.read_exact(&mut ip).await?;
            Host::Ip(Ipv6Addr::from(ip).into())
        }
        0x03 => {
            let len = tcp.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            tcp.read_exact(&mut name).await?;
            if !valid_hostname(&name) {
                write_reply(tcp, status::FAILURE, UNSPECIFIED).await?;
                return Ok(None);
            }
            Host::Domain(String::from_utf8(name).expect("validated ASCII"))
        }
        _ => {
            write_reply(tcp, ADDRESS_TYPE_NOT_SUPPORTED, UNSPECIFIED).await?;
            return Ok(None);
        }
    };
    let port = tcp.read_u16().await?;
    if request[1] != 0x01 {
        write_reply(tcp, COMMAND_NOT_SUPPORTED, UNSPECIFIED).await?;
        return Ok(None);
    }
    Ok(Some(Target { host, port }))
}

async fn write_reply(tcp: &mut TcpStream, code: u8, bound: SocketAddr) -> io::Result<()> {
    let mut reply = vec![5, code, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    tcp.write_all(&reply).await
}

/// Relay between a TCP connection and its session stream until the session
/// drops `writes`. The reader takes one permit per segment-sized read, and
/// one budget reservation per byte held.
pub async fn bridge(
    tcp: TcpStream,
    key: u64,
    segment: usize,
    events: mpsc::Sender<IoEvent>,
    permits: Arc<Semaphore>,
    mut writes: mpsc::Receiver<WriteCmd>,
    budget: Budget,
) {
    let (mut read_half, mut write_half) = tcp.into_split();
    let reader_events = events.clone();
    let reader = async move {
        loop {
            let Ok(permit) = permits.acquire().await else {
                break;
            };
            permit.forget();
            let mut reservation = budget.reserve(segment).await;
            let mut buf = vec![0u8; segment];
            let kind = match read_half.read(&mut buf).await {
                Ok(0) => IoKind::Eof,
                Ok(n) => {
                    buf.truncate(n);
                    reservation.shrink(n);
                    IoKind::Data(Chunk::reserved(buf, reservation))
                }
                Err(_) => IoKind::ReadError,
            };
            let more = matches!(kind, IoKind::Data(_));
            if reader_events.send(IoEvent { key, kind }).await.is_err() || !more {
                break;
            }
        }
        // Stay alive (keeping the read half open) until the writer finishes.
        std::future::pending::<()>().await;
    };
    let writer = async move {
        while let Some(command) = writes.recv().await {
            match command {
                WriteCmd::Data(chunk) => {
                    if write_half.write_all(chunk.as_ref()).await.is_err() {
                        let _ = events
                            .send(IoEvent {
                                key,
                                kind: IoKind::WriteError,
                            })
                            .await;
                        return;
                    }
                    drop(chunk);
                    let _ = events
                        .send(IoEvent {
                            key,
                            kind: IoKind::Written,
                        })
                        .await;
                }
                WriteCmd::Shutdown => {
                    let _ = write_half.shutdown().await;
                }
                WriteCmd::Reply(_) => {}
            }
        }
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
}
