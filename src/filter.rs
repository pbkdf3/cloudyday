//! Destination filtering and dialing on the server (§2, A.5).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use crate::wire::{Host, Target, status};

/// IPv4 ranges refused by default: this network, RFC 1918, CGNAT, loopback,
/// link-local (cloud metadata), IETF assignments, documentation,
/// benchmarking, 6to4 relay, multicast, and reserved (with broadcast).
const V4_REFUSED: &[(u32, u32)] = &[
    (0x0000_0000, 8),
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
];

/// IPv6 ranges refused by default: unspecified, loopback, local-use NAT64,
/// discard, IETF assignments (Teredo, benchmarking, ORCHID), documentation,
/// ULA, link-local, site-local, and multicast.
const V6_REFUSED: &[(u128, u32)] = &[
    (0, 128),
    (1, 128),
    (0x0064_ff9b_0001 << 80, 48),
    (0x0100 << 112, 64),
    (0x2001 << 112, 23),
    (0x2001_0db8 << 96, 32),
    (0x3fff << 112, 20),
    (0xfc00 << 112, 7),
    (0xfe80 << 112, 10),
    (0xfec0 << 112, 10),
    (0xff00 << 112, 8),
];

const NAT64: u128 = 0x0064_ff9b << 96;
const SIX_TO_FOUR: u128 = 0x2002 << 112;

/// Unwrap IPv4-mapped and IPv4-compatible IPv6 addresses.
pub fn normalize(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { return ip };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4.into();
    }
    let bits = u128::from(v6);
    if bits >> 32 == 0 && bits > 1 {
        return Ipv4Addr::from(bits as u32).into();
    }
    ip
}

fn v4_internal(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    V4_REFUSED
        .iter()
        .any(|&(base, len)| bits >> (32 - len) == base >> (32 - len))
}

fn v6_internal(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    // Translation prefixes embed IPv4 addresses; check those too.
    if bits >> 32 == NAT64 >> 32 {
        return v4_internal(Ipv4Addr::from(bits as u32));
    }
    if bits >> 112 == SIX_TO_FOUR >> 112 && v4_internal(Ipv4Addr::from((bits >> 80) as u32)) {
        return true;
    }
    V6_REFUSED
        .iter()
        .any(|&(base, len)| bits >> (128 - len) == base >> (128 - len))
}

/// Whether `ip` is in an internal range, after normalization.
pub fn is_internal(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v4) => v4_internal(v4),
        IpAddr::V6(v6) => v6_internal(v6),
    }
}

fn is_own_address(ip: IpAddr) -> bool {
    let ip = normalize(ip);
    if_addrs::get_if_addrs()
        .is_ok_and(|ifaces| ifaces.iter().any(|iface| normalize(iface.ip()) == ip))
}

/// The default destination filter: internal ranges and this host's own
/// interface addresses.
pub fn refused(ip: IpAddr) -> bool {
    is_internal(ip) || is_own_address(ip)
}

fn connect_status(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => status::CONNECTION_REFUSED,
        io::ErrorKind::NetworkUnreachable => status::NETWORK_UNREACHABLE,
        io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => status::HOST_UNREACHABLE,
        _ => status::FAILURE,
    }
}

/// Resolve and connect within the open deadline, checking every address
/// immediately before dialing it. Errors are OPEN_RESULT status codes.
pub async fn dial(
    target: &Target,
    deadline: Instant,
    allow_private: bool,
) -> Result<TcpStream, u8> {
    let addrs: Vec<SocketAddr> = match &target.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
        Host::Domain(name) => match timeout_at(
            deadline,
            tokio::net::lookup_host((name.as_str(), target.port)),
        )
        .await
        {
            Err(_) => return Err(status::TIMED_OUT),
            Ok(Err(e)) => {
                debug!(%target, %e, "name resolution failed");
                return Err(status::HOST_UNREACHABLE);
            }
            Ok(Ok(addrs)) => addrs.collect(),
        },
    };
    if addrs.is_empty() {
        return Err(status::HOST_UNREACHABLE);
    }
    let mut result = Err(status::NOT_ALLOWED);
    for addr in addrs {
        if !allow_private && refused(addr.ip()) {
            debug!(%target, %addr, "destination refused by filter");
            continue;
        }
        match timeout_at(deadline, TcpStream::connect(addr)).await {
            Err(_) => return Err(status::TIMED_OUT),
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                return Ok(tcp);
            }
            Ok(Err(e)) => {
                debug!(%target, %addr, %e, "connect failed");
                result = Err(connect_status(&e));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn internal(s: &str) -> bool {
        is_internal(s.parse().unwrap())
    }

    #[test]
    fn refused_ranges() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:c0a8:101::1",
            "fec0::1",
            "100::1",
        ] {
            assert!(internal(ip), "{ip} should be refused");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "203.0.114.1",
        ] {
            assert!(!internal(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn own_interfaces_refused() {
        assert!(refused("127.0.0.1".parse().unwrap()));
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                assert!(refused(iface.ip()), "{}", iface.ip());
            }
        }
    }

    #[tokio::test]
    async fn hostile_name_resolution_is_filtered() {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let target = Target {
            host: Host::Domain("localhost".into()),
            port: 9,
        };
        assert_eq!(
            dial(&target, deadline, false).await.unwrap_err(),
            status::NOT_ALLOWED
        );
        let target = Target {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: 9,
        };
        assert_eq!(
            dial(&target, deadline, false).await.unwrap_err(),
            status::NOT_ALLOWED
        );
    }
}
