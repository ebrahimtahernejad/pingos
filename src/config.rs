//! TOML config file loading + merging with CLI args.
//!
//! Precedence (highest wins):
//!   1. CLI args explicitly given by the user (clap `ValueSource::CommandLine`).
//!   2. Values from the TOML file.
//!   3. Built-in defaults (whatever clap's `default_value_t` provides).
//!
//! Detecting "the user typed this on the CLI" vs "this was a clap default"
//! uses `clap::ArgMatches::value_source`. So we keep clap's nice `--help`
//! defaults *and* let the TOML override them.
//!
//! Schema (all keys optional):
//!
//! ```toml
//! # ---- Common (apply to both subcommands) ----
//! log_level   = "info"     # or "debug" / "trace" / "warn" / "error"
//! verbose     = false      # true => log_level=debug (unless log_level set explicitly)
//! password    = "secret"
//! compression = "lz4"      # "none" or "lz4"
//! fec         = "8:2"      # "data:parity", or "0:0" to disable
//!
//! [client]
//! listen            = "127.0.0.1:4455"
//! server            = "tunnel.example.com"
//! target            = "10.0.0.1:80"
//! idle_timeout_secs = 60
//! max_conns         = 0
//!
//! [server]
//! bind              = "0.0.0.0"
//! dial_timeout_ms   = 5000
//! idle_timeout_secs = 60
//! max_conns         = 0
//! ```

use std::path::Path;

use anyhow::{Context, Result};
use clap::parser::ValueSource;
use clap::ArgMatches;
use serde::Deserialize;

use crate::cli::{ClientArgs, ServerArgs};
use crate::proto::Compression;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub log_level: Option<String>,
    #[serde(default)]
    pub verbose: bool,
    pub password: Option<String>,
    pub compression: Option<String>,
    pub fec: Option<String>,

    pub client: Option<ClientSection>,
    pub server: Option<ServerSection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub listen: Option<String>,
    pub server: Option<String>,
    pub target: Option<String>,
    pub idle_timeout_secs: Option<u64>,
    pub max_conns: Option<usize>,

    // Per-side overrides for the common fields. If set, they win over the
    // root-level common fields for this side.
    pub password: Option<String>,
    pub compression: Option<String>,
    pub fec: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub bind: Option<String>,
    pub dial_timeout_ms: Option<u64>,
    pub idle_timeout_secs: Option<u64>,
    pub max_conns: Option<usize>,

    pub password: Option<String>,
    pub compression: Option<String>,
    pub fec: Option<String>,
}

pub fn load(path: &Path) -> Result<ConfigFile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let cfg: ConfigFile = toml::from_str(&text)
        .with_context(|| format!("parsing TOML config {}", path.display()))?;
    Ok(cfg)
}

/// Resolve the effective log level given (in priority order):
///   1. CLI `--log-level <X>` (explicit)
///   2. CLI `--verbose` (=> "debug")
///   3. Config `log_level`
///   4. Config `verbose = true` (=> "debug")
///   5. Built-in default `"info"`
pub fn resolve_log_level(
    cli_log_level: Option<&str>,
    cli_verbose: bool,
    cfg: Option<&ConfigFile>,
) -> String {
    if let Some(s) = cli_log_level {
        return s.to_string();
    }
    if cli_verbose {
        return "debug".to_string();
    }
    if let Some(c) = cfg {
        if let Some(s) = &c.log_level {
            return s.clone();
        }
        if c.verbose {
            return "debug".to_string();
        }
    }
    "info".to_string()
}

/// Apply config defaults to `ClientArgs` for fields where the user didn't
/// supply a CLI value. `matches` is the `ArgMatches` for the `client`
/// subcommand. Returns the parsed FEC tuple (we re-parse strings from config).
pub fn merge_into_client(
    args: &mut ClientArgs,
    matches: &ArgMatches,
    cfg: Option<&ConfigFile>,
) -> Result<()> {
    let client_cfg = cfg.and_then(|c| c.client.as_ref());

    // listen/server/target are Option<String> on ClientArgs — they're required
    // (CLI or config), validated later in client::run. CLI value wins if present.
    if args.listen.is_none() {
        args.listen = client_cfg.and_then(|c| c.listen.clone());
    }
    if args.server.is_none() {
        args.server = client_cfg.and_then(|c| c.server.clone());
    }
    if args.target.is_none() {
        args.target = client_cfg.and_then(|c| c.target.clone());
    }
    if is_default(matches, "idle_timeout_secs") {
        if let Some(v) = client_cfg.and_then(|c| c.idle_timeout_secs) {
            args.idle_timeout_secs = v;
        }
    }
    if is_default(matches, "max_conns") {
        if let Some(v) = client_cfg.and_then(|c| c.max_conns) {
            args.max_conns = v;
        }
    }

    // Common fields (password / compression / fec): client-section value wins
    // over the root-level value if both are present.
    if is_default(matches, "password") {
        let v = client_cfg
            .and_then(|c| c.password.clone())
            .or_else(|| cfg.and_then(|c| c.password.clone()));
        if let Some(p) = v {
            args.password = p;
        }
    }
    if is_default(matches, "compression") {
        let v = client_cfg
            .and_then(|c| c.compression.clone())
            .or_else(|| cfg.and_then(|c| c.compression.clone()));
        if let Some(s) = v {
            args.compression = parse_compression(&s)?;
        }
    }
    if is_default(matches, "fec") {
        let v = client_cfg
            .and_then(|c| c.fec.clone())
            .or_else(|| cfg.and_then(|c| c.fec.clone()));
        if let Some(s) = v {
            args.fec = parse_fec_string(&s)?;
        }
    }
    Ok(())
}

pub fn merge_into_server(
    args: &mut ServerArgs,
    matches: &ArgMatches,
    cfg: Option<&ConfigFile>,
) -> Result<()> {
    let server_cfg = cfg.and_then(|c| c.server.as_ref());

    if is_default(matches, "bind") {
        if let Some(v) = server_cfg.and_then(|c| c.bind.clone()) {
            args.bind = v;
        }
    }
    if is_default(matches, "dial_timeout_ms") {
        if let Some(v) = server_cfg.and_then(|c| c.dial_timeout_ms) {
            args.dial_timeout_ms = v;
        }
    }
    if is_default(matches, "idle_timeout_secs") {
        if let Some(v) = server_cfg.and_then(|c| c.idle_timeout_secs) {
            args.idle_timeout_secs = v;
        }
    }
    if is_default(matches, "max_conns") {
        if let Some(v) = server_cfg.and_then(|c| c.max_conns) {
            args.max_conns = v;
        }
    }

    if is_default(matches, "password") {
        let v = server_cfg
            .and_then(|c| c.password.clone())
            .or_else(|| cfg.and_then(|c| c.password.clone()));
        if let Some(p) = v {
            args.password = p;
        }
    }
    if is_default(matches, "compression") {
        let v = server_cfg
            .and_then(|c| c.compression.clone())
            .or_else(|| cfg.and_then(|c| c.compression.clone()));
        if let Some(s) = v {
            args.compression = parse_compression(&s)?;
        }
    }
    if is_default(matches, "fec") {
        let v = server_cfg
            .and_then(|c| c.fec.clone())
            .or_else(|| cfg.and_then(|c| c.fec.clone()));
        if let Some(s) = v {
            args.fec = parse_fec_string(&s)?;
        }
    }
    Ok(())
}

fn is_default(matches: &ArgMatches, name: &str) -> bool {
    matches!(matches.value_source(name), Some(ValueSource::DefaultValue) | None)
}

fn parse_compression(s: &str) -> Result<Compression> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(Compression::None),
        "lz4" => Ok(Compression::Lz4),
        other => anyhow::bail!("invalid compression in config: {} (expected none|lz4)", other),
    }
}

fn parse_fec_string(s: &str) -> Result<(u8, u8)> {
    let (a, b) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("fec must be `data:parity`, got `{}`", s))?;
    let n: u8 = a
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid data shards in fec: `{}`", a))?;
    let k: u8 = b
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid parity shards in fec: `{}`", b))?;
    if n == 0 && k == 0 {
        return Ok((0, 0));
    }
    if n == 0 || k == 0 {
        anyhow::bail!("fec data and parity must both be > 0 (or both 0 to disable)");
    }
    if (n as u16) + (k as u16) > 128 {
        anyhow::bail!("fec data + parity must be <= 128");
    }
    Ok((n, k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_simple_config() {
        let toml_src = r#"
            log_level = "debug"
            password = "hunter2"
            compression = "lz4"
            fec = "8:2"

            [client]
            listen = "127.0.0.1:4455"
            server = "example.com"
            target = "10.0.0.1:80"

            [server]
            bind = "0.0.0.0"
            dial_timeout_ms = 3000
        "#;
        let cfg: ConfigFile = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
        assert_eq!(cfg.password.as_deref(), Some("hunter2"));
        let client = cfg.client.unwrap();
        assert_eq!(client.listen.as_deref(), Some("127.0.0.1:4455"));
        let server = cfg.server.unwrap();
        assert_eq!(server.dial_timeout_ms, Some(3000));
    }

    #[test]
    fn rejects_unknown_field() {
        let toml_src = r#"
            unknown_key = 1
        "#;
        let res: Result<ConfigFile, _> = toml::from_str(toml_src);
        assert!(res.is_err());
    }

    #[test]
    fn verbose_promotes_log_level_to_debug() {
        let cfg = ConfigFile {
            verbose: true,
            ..Default::default()
        };
        assert_eq!(resolve_log_level(None, false, Some(&cfg)), "debug");
    }

    #[test]
    fn cli_log_level_beats_verbose_in_config() {
        let cfg = ConfigFile {
            verbose: true,
            log_level: Some("warn".to_string()),
            ..Default::default()
        };
        // CLI explicit > config
        assert_eq!(resolve_log_level(Some("trace"), false, Some(&cfg)), "trace");
        // No CLI, log_level in config beats verbose=true
        assert_eq!(resolve_log_level(None, false, Some(&cfg)), "warn");
        // CLI --verbose beats config log_level
        assert_eq!(resolve_log_level(None, true, Some(&cfg)), "debug");
    }

    #[test]
    fn parse_fec_works() {
        assert_eq!(parse_fec_string("8:2").unwrap(), (8, 2));
        assert_eq!(parse_fec_string("0:0").unwrap(), (0, 0));
        assert!(parse_fec_string("8:0").is_err());
        assert!(parse_fec_string("nope").is_err());
    }
}
