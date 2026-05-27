use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::proto::Compression;

#[derive(Parser, Debug)]
#[command(
    name = "pingos",
    about = "TCP-over-ICMP tunnel (client + server). TCP-only, encrypted, event-driven.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Log level (trace, debug, info, warn, error). Honors RUST_LOG too.
    #[arg(long, global = true)]
    pub log_level: Option<String>,

    /// Verbose output (shortcut for --log-level=debug).
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Path to a TOML config file. CLI flags override config values; config
    /// values override built-in defaults.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a client: listens on a local TCP port and tunnels to a server over ICMP.
    Client(ClientArgs),

    /// Run a server: receives ICMP from clients and forwards TCP to the requested target.
    Server(ServerArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ClientArgs {
    /// Local TCP address to listen on (e.g. 127.0.0.1:4455). Required (CLI or config).
    #[arg(short = 'l', long = "listen")]
    pub listen: Option<String>,

    /// Server hostname or IP that hosts the pingos server. Required (CLI or config).
    #[arg(short = 's', long = "server")]
    pub server: Option<String>,

    /// Target address the server should connect to for each tunneled stream (host:port).
    /// Required (CLI or config).
    #[arg(short = 't', long = "target")]
    pub target: Option<String>,

    /// Password used to derive the encryption key (empty = no encryption).
    #[arg(short = 'p', long = "password", default_value = "")]
    pub password: String,

    /// Per-connection idle timeout in seconds.
    #[arg(long, default_value_t = 60)]
    pub idle_timeout_secs: u64,

    /// Max concurrent tunneled connections (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    pub max_conns: usize,

    /// On-wire compression. Must match the server.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    pub compression: Compression,

    /// Forward-error-correction group size as `data:parity`, e.g. `8:2`. Must
    /// match the server. Disabled by default; pass `0:0` (or omit) to disable.
    #[arg(long, value_parser = parse_fec, default_value = "0:0")]
    pub fec: (u8, u8),
}

#[derive(Args, Debug, Clone)]
pub struct ServerArgs {
    /// Local address to bind the ICMP listener to.
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,

    /// Password used to derive the encryption key (empty = no encryption).
    #[arg(short = 'p', long = "password", default_value = "")]
    pub password: String,

    /// Dial timeout (ms) when connecting to the upstream target.
    #[arg(long, default_value_t = 5000)]
    pub dial_timeout_ms: u64,

    /// Per-connection idle timeout in seconds.
    #[arg(long, default_value_t = 60)]
    pub idle_timeout_secs: u64,

    /// Max concurrent tunneled connections (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    pub max_conns: usize,

    /// On-wire compression. Must match the client.
    #[arg(long, value_enum, default_value_t = Compression::None)]
    pub compression: Compression,

    /// Forward-error-correction group size as `data:parity`, e.g. `8:2`. Must
    /// match the client. Disabled by default; pass `0:0` (or omit) to disable.
    #[arg(long, value_parser = parse_fec, default_value = "0:0")]
    pub fec: (u8, u8),
}

fn parse_fec(s: &str) -> Result<(u8, u8), String> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| format!("expected format `data:parity`, got `{}`", s))?;
    let n: u8 = a
        .parse()
        .map_err(|_| format!("invalid data shards: `{}`", a))?;
    let k: u8 = b
        .parse()
        .map_err(|_| format!("invalid parity shards: `{}`", b))?;
    if n == 0 && k == 0 {
        return Ok((0, 0));
    }
    if n == 0 || k == 0 {
        return Err("both data and parity must be > 0 (or both 0 to disable)".into());
    }
    let total = n as u16 + k as u16;
    if total > 128 {
        return Err(format!("data + parity must be <= 128 (got {})", total));
    }
    Ok((n, k))
}
