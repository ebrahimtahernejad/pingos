use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use pingos::{cli, client, config, server};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::Cli::command().get_matches();
    let mut args = cli::Cli::from_arg_matches(&matches)
        .map_err(|e| anyhow::anyhow!("argument parse error: {}", e))?;

    let cfg = match &args.config {
        Some(path) => Some(
            config::load(path).with_context(|| format!("loading {}", path.display()))?,
        ),
        None => None,
    };

    let log_level = config::resolve_log_level(args.log_level.as_deref(), args.verbose, cfg.as_ref());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level.clone())),
        )
        .with_target(false)
        .init();

    if let Some(p) = &args.config {
        tracing::info!(config = %p.display(), "loaded TOML config");
    }
    tracing::debug!(log_level = %log_level, "log level resolved");

    match &mut args.command {
        cli::Command::Client(c) => {
            let sub = matches
                .subcommand_matches("client")
                .expect("clap should have selected client");
            config::merge_into_client(c, sub, cfg.as_ref())?;
            client::run(c.clone()).await
        }
        cli::Command::Server(s) => {
            let sub = matches
                .subcommand_matches("server")
                .expect("clap should have selected server");
            config::merge_into_server(s, sub, cfg.as_ref())?;
            server::run(s.clone()).await
        }
    }
}
