//! Command line, key loading, logging, and startup.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::crypto::{SECRET_MIN_LEN, SharedSecret};
use crate::dns::TunnelDomain;
use crate::session::client::{Client, ClientOptions};
use crate::session::server::{Server, ServerOptions};
/// New secrets contain 256 bits of OS randomness.
pub const GENERATED_KEY_LEN: usize = SECRET_MIN_LEN;
/// Default shared-secret file, relative to the working directory. Deliberately
/// different from v1's xor.key: old XOR keys may already have been recovered.
pub const DEFAULT_KEY_FILE: &str = "shared.key";

#[derive(Parser)]
#[command(
    name = "cloudyday",
    version,
    about = "A SOCKS5 TCP proxy carried over DNS"
)]
struct Cli {
    /// Log more (-v for debug, -vv for trace)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Log only warnings and errors
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Answer tunnel queries as the domain's authoritative DNS server
    Server {
        /// Tunnel domain delegated to this server
        #[arg(long)]
        domain: String,
        /// UDP address for DNS
        #[arg(long, default_value = "0.0.0.0:53")]
        listen: SocketAddr,
        /// Shared-secret file (raw random bytes, at least 32). Without this
        /// option, shared.key is used and generated if missing
        #[arg(long, alias = "xor-key-file")]
        key_file: Option<PathBuf>,
        /// Allow loopback, private, and other internal destinations
        #[arg(long)]
        allow_private_destinations: bool,
        /// Open a SOCKS5 proxy through the newest connected client
        #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:1080", value_name = "ADDR")]
        reverse_socks: Option<SocketAddr>,
    },
    /// Accept SOCKS5 CONNECT locally and tunnel it through a resolver
    Client {
        /// Tunnel domain delegated to the server
        #[arg(long)]
        domain: String,
        /// Recursive resolver to send queries to
        #[arg(long)]
        resolver: SocketAddr,
        /// SOCKS5 listen address
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        /// Shared-secret file (raw random bytes, at least 32); a copy of
        /// the server's secret file [default: shared.key]
        #[arg(long, alias = "xor-key-file")]
        key_file: Option<PathBuf>,
    },
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match (cli.quiet, cli.verbose) {
        (true, _) => "warn",
        (false, 0) => "info",
        (false, 1) => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Read the shared secret as raw bytes, without trimming.
pub fn load_key(path: &Path) -> Result<SharedSecret, String> {
    let bytes = std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "shared-secret file {} not found; copy the server's secret file there or pass --key-file",
            path.display()
        ),
        _ => format!("cannot read shared-secret file {}: {e}", path.display()),
    })?;
    SharedSecret::new(bytes).ok_or_else(|| format!("shared-secret file {} is empty or shorter than {SECRET_MIN_LEN} bytes; use a random secret, not a password", path.display()))
}

/// Write a new random key to `path`, owner-readable only. Never overwrites
/// an existing file.
pub fn generate_key(path: &Path) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut key = vec![0u8; GENERATED_KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| format!("cannot generate shared secret: {e}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create shared-secret file {}: {e}", path.display()))?;
    file.write_all(&key)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write shared-secret file {}: {e}", path.display()))
}

/// The server's secret: an explicit file, or generated/reused shared.key.
pub fn server_key(path: Option<&Path>) -> Result<(SharedSecret, bool), String> {
    let Some(path) = path else {
        return load_or_create_key(Path::new(DEFAULT_KEY_FILE));
    };
    Ok((load_key(path)?, false))
}

fn load_or_create_key(path: &Path) -> Result<(SharedSecret, bool), String> {
    let created = !path.exists();
    if created {
        generate_key(path)?;
    }
    Ok((load_key(path)?, created))
}

/// The client's secret: the given file or shared.key. Never created.
pub fn client_key(path: Option<&Path>) -> Result<SharedSecret, String> {
    load_key(path.unwrap_or(Path::new(DEFAULT_KEY_FILE)))
}

fn parse_domain(domain: &str) -> Result<TunnelDomain, String> {
    let domain = TunnelDomain::parse(domain)?;
    domain.sizes()?;
    Ok(domain)
}

fn warn_no_integrity() {
    warn!(
        "shared-secret authentication is handshake-only: plain ChaCha20 has no packet integrity; \
         active attackers can modify traffic or forge public errors; use application-level TLS; \
         there is no forward secrecy and SOCKS listeners have no authentication"
    );
}

fn run(command: Command) -> Result<(), String> {
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    let result = match command {
        Command::Server {
            domain,
            listen,
            key_file,
            allow_private_destinations,
            reverse_socks,
        } => {
            let domain = parse_domain(&domain)?;
            let (key, created) = server_key(key_file.as_deref())?;
            if created {
                info!(
                    path = DEFAULT_KEY_FILE,
                    bytes = GENERATED_KEY_LEN,
                    "generated a new shared secret; copy this file to the client"
                );
            }
            warn_no_integrity();
            if allow_private_destinations {
                warn!(
                    "--allow-private-destinations: internal addresses are reachable through this proxy"
                );
            }
            if let Some(addr) = reverse_socks {
                warn!(%addr, "reverse SOCKS can access the connected client's private network; newest client wins");
                if !addr.ip().is_loopback() {
                    warn!(%addr, "reverse SOCKS listener is not on loopback and has no authentication");
                }
            }
            let sizes = domain.sizes()?;
            runtime.block_on(async {
                let options = ServerOptions { domain: domain.clone(), key, allow_private: allow_private_destinations, reverse_socks };
                let server = Server::bind(listen, options).await?;
                info!(listen = %server.local_addr()?, %domain, u = sizes.u, d = sizes.d, "server ready");
                tokio::select! {
                    result = server.run() => result,
                    _ = tokio::signal::ctrl_c() => Ok(()),
                }
            })
        }
        Command::Client {
            domain,
            resolver,
            listen,
            key_file,
        } => {
            let domain = parse_domain(&domain)?;
            let key = client_key(key_file.as_deref())?;
            warn_no_integrity();
            warn!(
                "the client always supports reverse SOCKS: the server can dial destinations on this client's network"
            );
            if !listen.ip().is_loopback() {
                warn!(%listen, "SOCKS listener is not on a loopback address and has no authentication");
            }
            runtime.block_on(async {
                let client = Client::bind(
                    listen,
                    resolver,
                    ClientOptions {
                        domain: domain.clone(),
                        key,
                    },
                )
                .await?;
                info!(socks = %client.socks_addr()?, %resolver, %domain, "client ready");
                tokio::select! {
                    result = client.run() => result,
                    _ = tokio::signal::ctrl_c() => Ok(()),
                }
            })
        }
    };
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_loading() {
        let dir = std::env::temp_dir().join(format!("cloudyday-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(load_key(&empty).unwrap_err().contains("empty"));
        assert!(
            load_key(&dir.join("missing"))
                .unwrap_err()
                .contains("not found")
        );
        let raw = dir.join("raw");
        std::fs::write(&raw, b" key\n").unwrap();
        assert!(load_key(&raw).unwrap_err().contains("shorter"));
        // Exactly 32 raw bytes including spaces and a trailing newline; a
        // trimming loader would incorrectly reject this file.
        let mut bytes = [b' '; 32];
        bytes[31] = b'\n';
        std::fs::write(&raw, bytes).unwrap();
        assert!(load_key(&raw).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn key_generation() {
        let dir = std::env::temp_dir().join(format!("cloudyday-gen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key");
        generate_key(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        assert_eq!(first.len(), GENERATED_KEY_LEN);
        assert!(load_key(&path).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let err = generate_key(&path).unwrap_err();
        assert!(err.contains("cannot create"), "{err}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            first,
            "existing key untouched"
        );
        let other = dir.join("other");
        generate_key(&other).unwrap();
        assert_ne!(std::fs::read(&other).unwrap(), first);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn default_key_file() {
        let dir =
            std::env::temp_dir().join(format!("cloudyday-default-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DEFAULT_KEY_FILE);
        // Missing: the client errors and creates nothing; the server creates it.
        assert!(load_key(&path).unwrap_err().contains("not found"));
        assert!(!path.exists());
        let (_, created) = load_or_create_key(&path).unwrap();
        assert!(created);
        let first = std::fs::read(&path).unwrap();
        assert_eq!(first.len(), GENERATED_KEY_LEN);
        // Present: reused unchanged.
        let (_, created) = load_or_create_key(&path).unwrap();
        assert!(!created);
        assert_eq!(std::fs::read(&path).unwrap(), first);
        // An explicit path is never created.
        let explicit = dir.join("explicit.key");
        assert!(server_key(Some(&explicit)).is_err());
        assert!(client_key(Some(&explicit)).is_err());
        assert!(!explicit.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cli_parses() {
        Cli::command_for_test();
    }

    impl Cli {
        fn command_for_test() {
            use clap::CommandFactory;
            Cli::command().debug_assert();
            let cli = Cli::try_parse_from([
                "cloudyday",
                "client",
                "--domain",
                "t.example.com",
                "--resolver",
                "192.0.2.53:53",
                "--key-file",
                "/k",
            ])
            .unwrap();
            let Command::Client { listen, .. } = cli.command else {
                panic!()
            };
            assert_eq!(listen, "127.0.0.1:1080".parse().unwrap());
            let alias = Cli::try_parse_from([
                "cloudyday",
                "server",
                "--domain",
                "t.example.com",
                "--xor-key-file",
                "/legacy-spelling",
            ])
            .unwrap();
            assert!(
                matches!(alias.command, Command::Server { key_file: Some(path), .. }
                if path == Path::new("/legacy-spelling"))
            );
            let cli =
                Cli::try_parse_from(["cloudyday", "server", "--domain", "t.example.com"]).unwrap();
            let Command::Server {
                key_file,
                reverse_socks,
                ..
            } = cli.command
            else {
                panic!()
            };
            assert_eq!(key_file, None, "key file optional");
            assert_eq!(reverse_socks, None);
            let cli = Cli::try_parse_from([
                "cloudyday",
                "server",
                "--domain",
                "t.example.com",
                "--reverse-socks",
            ])
            .unwrap();
            let Command::Server { reverse_socks, .. } = cli.command else {
                panic!()
            };
            assert_eq!(reverse_socks, Some("127.0.0.1:1080".parse().unwrap()));
            let cli = Cli::try_parse_from([
                "cloudyday",
                "server",
                "--domain",
                "t.example.com",
                "--reverse-socks",
                "127.0.0.1:2080",
            ])
            .unwrap();
            let Command::Server { reverse_socks, .. } = cli.command else {
                panic!()
            };
            assert_eq!(reverse_socks, Some("127.0.0.1:2080".parse().unwrap()));
            assert!(
                Cli::try_parse_from(["cloudyday", "server", "--domain", "x", "--generate-xor-key"])
                    .is_err()
            );
        }
    }
}
