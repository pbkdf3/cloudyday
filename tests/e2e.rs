//! Real sockets: SOCKS5 client -> cloudyday client -> lossy UDP relay
//! (standing in for a recursive resolver) -> cloudyday server -> TCP echo.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cloudyday::crypto::SharedSecret;
use cloudyday::dns::TunnelDomain;
use cloudyday::session::client::{Client, ClientOptions};
use cloudyday::session::server::{Server, ServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

fn domain() -> TunnelDomain {
    TunnelDomain::parse("tunnel.example.net").unwrap()
}

fn key() -> SharedSecret {
    SharedSecret::new(vec![0x42; 32]).unwrap()
}

async fn start_server(allow_private: bool) -> SocketAddr {
    let options = ServerOptions {
        domain: domain(),
        key: key(),
        allow_private,
        reverse_socks: None,
    };
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), options)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.run());
    addr
}

/// Forwards client queries to the server and responses back, dropping and
/// duplicating datagrams and delaying them by a random amount.
async fn start_relay(server: SocketAddr, loss_percent: u64, dup_percent: u64) -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let seed = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let rand = move || {
        let mut x = seed.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        seed.store(x, Ordering::Relaxed);
        x
    };
    tokio::spawn(async move {
        let mut client = None;
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, src)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let dest = if src == server {
                match client {
                    Some(c) => c,
                    None => continue,
                }
            } else {
                client = Some(src);
                server
            };
            if rand() % 100 < loss_percent {
                continue;
            }
            let copies = if rand() % 100 < dup_percent { 2 } else { 1 };
            for _ in 0..copies {
                let packet = buf[..n].to_vec();
                let socket = socket.clone();
                let delay = Duration::from_millis(rand() % 30);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&packet, dest).await;
                });
            }
        }
    });
    addr
}

async fn start_client(resolver: SocketAddr) -> SocketAddr {
    let options = ClientOptions {
        domain: domain(),
        key: key(),
    };
    let client = Client::bind("127.0.0.1:0".parse().unwrap(), resolver, options)
        .await
        .unwrap();
    let addr = client.socks_addr().unwrap();
    tokio::spawn(client.run());
    addr
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut rd, mut wr) = tcp.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

/// SOCKS5 CONNECT; returns the reply code and the connected stream.
async fn socks_connect(proxy: SocketAddr, request: &[u8]) -> (u8, TcpStream) {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    tcp.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    tcp.write_all(request).await.unwrap();
    let mut reply = [0u8; 4];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    let rest = match reply[3] {
        1 => 6,
        4 => 18,
        other => panic!("reply address type {other}"),
    };
    let mut bound = vec![0u8; rest];
    tcp.read_exact(&mut bound).await.unwrap();
    (reply[1], tcp)
}

fn connect_ip(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = addr else { panic!() };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.ip().octets());
    request.extend_from_slice(&v4.port().to_be_bytes());
    request
}

fn connect_name(name: &str, port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request
}

async fn echo_through(proxy: SocketAddr, echo: SocketAddr, len: usize, seed: u8) {
    let (code, tcp) = socks_connect(proxy, &connect_ip(echo)).await;
    assert_eq!(code, 0);
    let data: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
        .collect();
    let (mut rd, mut wr) = tcp.into_split();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&sent).await.unwrap();
        // Half-close: the echo server sees EOF and closes after echoing.
        wr.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    rd.read_to_end(&mut received).await.unwrap();
    writer.await.unwrap();
    assert_eq!(received.len(), data.len());
    assert!(received == data, "echoed bytes differ");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_echo_through_lossy_resolver() {
    let server = start_server(true).await;
    let relay = start_relay(server, 10, 5).await;
    let proxy = start_client(relay).await;
    let echo = start_echo().await;
    let transfers = (0..4).map(|i| echo_through(proxy, echo, 40_000 + i * 7_919, i as u8));
    timeout(Duration::from_secs(120), futures_join(transfers.collect()))
        .await
        .expect("transfers timed out");
}

async fn futures_join(tasks: Vec<impl Future<Output = ()> + Send + 'static>) {
    let handles: Vec<_> = tasks.into_iter().map(tokio::spawn).collect();
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_filter_and_socks_errors() {
    let server = start_server(false).await;
    let relay = start_relay(server, 0, 0).await;
    let proxy = start_client(relay).await;
    let echo = start_echo().await;
    let run = async {
        // Loopback by address and through name resolution: not allowed.
        let (code, _) = socks_connect(proxy, &connect_ip(echo)).await;
        assert_eq!(code, 0x02);
        let (code, _) = socks_connect(proxy, &connect_name("localhost", echo.port())).await;
        assert_eq!(code, 0x02);
        // Unsupported command and address type.
        let mut bind = connect_ip(echo);
        bind[1] = 2;
        let (code, _) = socks_connect(proxy, &bind).await;
        assert_eq!(code, 0x07);
        let mut tcp = TcpStream::connect(proxy).await.unwrap();
        tcp.write_all(&[5, 1, 0, 5, 1, 0, 9]).await.unwrap();
        let mut reply = [0u8; 4];
        tcp.read_exact(&mut reply[..2]).await.unwrap();
        tcp.read_exact(&mut reply[..2]).await.unwrap();
        assert_eq!(reply[..2], [5, 0x08]);
        // Only "no authentication" is offered.
        let mut tcp = TcpStream::connect(proxy).await.unwrap();
        tcp.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0u8; 2];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xff]);
    };
    timeout(Duration::from_secs(60), run)
        .await
        .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_refused_is_relayed() {
    let server = start_server(true).await;
    let relay = start_relay(server, 0, 0).await;
    let proxy = start_client(relay).await;
    // Bind and drop a listener to get a closed port.
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let run = async {
        let (code, mut tcp) = socks_connect(proxy, &connect_ip(closed)).await;
        assert_eq!(code, 0x05);
        let mut rest = Vec::new();
        tcp.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    };
    timeout(Duration::from_secs(60), run)
        .await
        .expect("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_key_never_connects() {
    let server = start_server(true).await;
    let relay = start_relay(server, 0, 0).await;
    let options = ClientOptions {
        domain: domain(),
        key: SharedSecret::new(vec![0x43; 32]).unwrap(),
    };
    let client = Client::bind("127.0.0.1:0".parse().unwrap(), relay, options)
        .await
        .unwrap();
    let proxy = client.socks_addr().unwrap();
    tokio::spawn(client.run());
    let echo = start_echo().await;
    let (code, _) = timeout(
        Duration::from_secs(45),
        socks_connect(proxy, &connect_ip(echo)),
    )
    .await
    .expect("timed out");
    assert_eq!(code, 0x01);
}

async fn start_reverse_server(allow_private: bool) -> (SocketAddr, SocketAddr) {
    // The real listener must not bind until a session exists. Reserve an unused
    // port briefly so the test can discover its configured address beforehand.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = probe.local_addr().unwrap();
    drop(probe);
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        ServerOptions {
            domain: domain(),
            key: key(),
            allow_private,
            reverse_socks: Some(proxy),
        },
    )
    .await
    .unwrap();
    let dns = server.local_addr().unwrap();
    tokio::spawn(server.run());
    (dns, proxy)
}

async fn wait_for_proxy(proxy: SocketAddr) {
    timeout(Duration::from_secs(15), async {
        loop {
            if TcpStream::connect(proxy).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reverse SOCKS listener did not open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_socks_through_lossy_resolver() {
    let (dns, proxy) = start_reverse_server(true).await;
    assert!(
        TcpStream::connect(proxy).await.is_err(),
        "no listener before a client connects"
    );
    let relay = start_relay(dns, 10, 5).await;
    let forward = start_client(relay).await; // No local SOCKS request needed.
    wait_for_proxy(proxy).await;
    let echo = start_echo().await;
    // Both directions can carry concurrent streams and half-closes, without
    // confusing stream IDs or starving either direction of its query budget.
    let transfers = vec![
        echo_through(proxy, echo, 30_000, 1),
        echo_through(proxy, echo, 35_000, 2),
        echo_through(forward, echo, 25_000, 3),
    ];
    timeout(Duration::from_secs(120), futures_join(transfers))
        .await
        .expect("reverse transfers timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_resolves_on_client_and_reaches_private_destinations() {
    let (dns, proxy) = start_reverse_server(false).await;
    let forward = start_client(dns).await;
    wait_for_proxy(proxy).await;
    let echo = start_echo().await;
    timeout(Duration::from_secs(30), async {
        // Server destination filtering still applies to the forward proxy, but
        // reverse SOCKS deliberately allows the client's LAN and loopback.
        let (code, _) = socks_connect(forward, &connect_ip(echo)).await;
        assert_eq!(code, 0x02);
        let (code, mut tcp) = socks_connect(proxy, &connect_name("localhost", echo.port())).await;
        assert_eq!(code, 0);
        tcp.write_all(b"reverse hostname").await.unwrap();
        tcp.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        tcp.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"reverse hostname");
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (code, _) = socks_connect(proxy, &connect_ip(closed)).await;
        assert_eq!(code, 0x05, "client's connection-refused status is relayed");
    })
    .await
    .expect("reverse name/error test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newest_client_wins_and_old_client_does_not_reclaim_proxy() {
    let (dns, proxy) = start_reverse_server(true).await;
    let old_forward = start_client(dns).await;
    wait_for_proxy(proxy).await;
    let echo = start_echo().await;
    let (code, mut old_connection) = timeout(
        Duration::from_secs(15),
        socks_connect(proxy, &connect_ip(echo)),
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    let new_forward = start_client(dns).await;
    timeout(Duration::from_secs(15), async {
        let mut byte = [0];
        // Existing SOCKS connections belong to the displaced client and close.
        match old_connection.read(&mut byte).await {
            Ok(n) => assert_eq!(n, 0),
            Err(e) => assert!(matches!(e.kind(), std::io::ErrorKind::ConnectionReset)),
        }
        // Give the old client's idle poll time to receive REPLACED.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (code, _) = socks_connect(old_forward, &connect_ip(echo)).await;
        assert_eq!(
            code, 0x01,
            "displaced client must not reconnect automatically"
        );
        echo_through(proxy, echo, 1_000, 4).await;
        echo_through(new_forward, echo, 1_000, 5).await;
    })
    .await
    .expect("client replacement timed out");
}
