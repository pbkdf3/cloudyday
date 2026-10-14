//! Command line, key loading, logging, and startup.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::dns::TunnelDomain;
use crate::session::client::{Client, ClientOptions};
use crate::session::server::{Server, ServerOptions};
use crate::wire::XorKey;

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
        /// File holding the shared XOR key (raw bytes, nonempty)
        #[arg(long)]
        xor_key_file: PathBuf,
        /// Allow loopback, private, and other internal destinations
        #[arg(long)]
        allow_private_destinations: bool,
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
        /// File holding the shared XOR key (raw bytes, nonempty)
        #[arg(long)]
        xor_key_file: PathBuf,
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

/// Read the key as raw bytes, without trimming. Missing or empty is fatal.
pub fn load_key(path: &Path) -> Result<XorKey, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read XOR key file {}: {e}", path.display()))?;
    XorKey::new(bytes).ok_or_else(|| format!("XOR key file {} is empty", path.display()))
}

fn parse_domain(domain: &str) -> Result<TunnelDomain, String> {
    let domain = TunnelDomain::parse(domain)?;
    domain.sizes()?;
    Ok(domain)
}

fn warn_unauthenticated() {
    warn!(
        "the tunnel has no authentication: XOR obfuscation is not encryption or access control, \
         an observer can recover the key and forge traffic, and the server is an open proxy; \
         use application-level TLS for confidentiality"
    );
}

fn run(command: Command) -> Result<(), String> {
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    let result = match command {
        Command::Server {
            domain,
            listen,
            xor_key_file,
            allow_private_destinations,
        } => {
            let domain = parse_domain(&domain)?;
            let key = load_key(&xor_key_file)?;
            warn_unauthenticated();
            if allow_private_destinations {
                warn!(
                    "--allow-private-destinations: internal addresses are reachable through this proxy"
                );
            }
            let sizes = domain.sizes()?;
            runtime.block_on(async {
                let options = ServerOptions { domain: domain.clone(), key, allow_private: allow_private_destinations };
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
            xor_key_file,
        } => {
            let domain = parse_domain(&domain)?;
            let key = load_key(&xor_key_file)?;
            warn_unauthenticated();
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
                .contains("cannot read")
        );
        let raw = dir.join("raw");
        std::fs::write(&raw, b" key\n").unwrap();
        let key = load_key(&raw).unwrap();
        let mut data = [0u8; 5];
        key.apply(&mut data);
        assert_eq!(&data, b" key\n", "key bytes are used without trimming");
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
                "--xor-key-file",
                "/k",
            ])
            .unwrap();
            let Command::Client { listen, .. } = cli.command else {
                panic!()
            };
            assert_eq!(listen, "127.0.0.1:1080".parse().unwrap());
            assert!(
                Cli::try_parse_from(["cloudyday", "server", "--domain", "t.example.com"]).is_err(),
                "key file required"
            );
        }
    }
}
