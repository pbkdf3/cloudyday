//! Command line, embedded key initialization, logging, and startup.

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::{ArgAction, Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::dns::TunnelDomain;
use crate::embedded_key;
use crate::session::client::{Client, ClientOptions};
use crate::session::server::{Server, ServerOptions};

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
        /// Tunnel domain delegated to this server (required unless --genkey)
        #[arg(long, required_unless_present = "genkey")]
        domain: Option<String>,
        /// UDP address for DNS
        #[arg(long, default_value = "0.0.0.0:53")]
        listen: SocketAddr,
        /// Embed a new random key in this executable (replacing any old key), then exit
        #[arg(long)]
        genkey: bool,
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

fn report_generated_key() {
    info!(
        "embedded a new shared secret in this executable; securely copy the executable to the client"
    );
    warn!(
        "executable replaced with mode 0700; file capabilities were not preserved; reapply setcap if needed"
    );
}

fn run(command: Command) -> Result<(), String> {
    // Key-only operation must not require a domain, a Tokio runtime, or sockets.
    if matches!(&command, Command::Server { genkey: true, .. }) {
        embedded_key::server(true)?;
        report_generated_key();
        return Ok(());
    }
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| format!("cannot start runtime: {e}"))?;
    let result = match command {
        Command::Server {
            domain,
            listen,
            genkey: _,
            allow_private_destinations,
            reverse_socks,
        } => {
            let domain = parse_domain(domain.as_deref().ok_or("--domain is required")?)?;
            let (key, created) = embedded_key::server(false)?;
            if created {
                report_generated_key();
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
        } => {
            let domain = parse_domain(&domain)?;
            let key = embedded_key::load()?;
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
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "cloudyday",
            "client",
            "--domain",
            "t.example.com",
            "--resolver",
            "192.0.2.53:53",
        ])
        .unwrap();
        let Command::Client { listen, .. } = cli.command else {
            panic!()
        };
        assert_eq!(listen, "127.0.0.1:1080".parse().unwrap());
        let cli = Cli::try_parse_from(["cloudyday", "server", "--genkey"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Server {
                domain: None,
                genkey: true,
                ..
            }
        ));
        assert!(Cli::try_parse_from(["cloudyday", "server"]).is_err());
        assert!(Cli::try_parse_from(["cloudyday", "client", "--genkey"]).is_err());
        let cli =
            Cli::try_parse_from(["cloudyday", "server", "--domain", "t.example.com"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Server {
                genkey: false,
                reverse_socks: None,
                ..
            }
        ));
        for (args, expected) in [
            (
                vec![
                    "cloudyday",
                    "server",
                    "--domain",
                    "t.example.com",
                    "--reverse-socks",
                ],
                "127.0.0.1:1080",
            ),
            (
                vec![
                    "cloudyday",
                    "server",
                    "--domain",
                    "t.example.com",
                    "--reverse-socks",
                    "127.0.0.1:2080",
                ],
                "127.0.0.1:2080",
            ),
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let Command::Server { reverse_socks, .. } = cli.command else {
                panic!()
            };
            assert_eq!(reverse_socks, Some(expected.parse().unwrap()));
        }
        for option in ["--key-file", "--xor-key-file", "--generate-xor-key"] {
            assert!(
                Cli::try_parse_from(["cloudyday", "server", "--domain", "x", option, "/k"])
                    .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "cloudyday",
                    "client",
                    "--domain",
                    "x",
                    "--resolver",
                    "127.0.0.1:53",
                    option,
                    "/k"
                ])
                .is_err()
            );
        }
    }
}
