//! Bot Management Agent for Zentinel
//!
//! Detects bots through multiple signals and returns bot scores.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use zentinel_agent_bot_management::{BotManagementAgent, BotManagementConfig};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};

#[derive(Parser, Debug)]
#[command(name = "zentinel-bot-management-agent")]
#[command(
    author,
    version,
    about = "Bot detection and management agent for Zentinel"
)]
struct Args {
    /// Unix socket path for the agent server (v2 UDS transport)
    #[arg(short, long, default_value = "/tmp/zentinel-bot-management.sock")]
    socket: PathBuf,

    /// gRPC address for the agent server (v2 gRPC transport)
    /// When specified, gRPC transport is used instead of Unix socket
    #[arg(long)]
    grpc_address: Option<String>,

    /// Path to configuration file (JSON or YAML)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to known good bots database
    #[arg(long, default_value = "data/good_bots.json")]
    good_bots: PathBuf,

    /// Path to bad patterns database
    #[arg(long, default_value = "data/bad_patterns.json")]
    bad_patterns: PathBuf,

    /// Enable JSON logging format
    #[arg(long)]
    json_logs: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn init_logging(json: bool, level: &str) {
    let level = match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let env_filter = EnvFilter::from_default_env().add_directive(level.into());

    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(args.json_logs, &args.log_level);

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        let content = std::fs::read_to_string(config_path)?;
        if config_path
            .extension()
            .is_some_and(|e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        BotManagementConfig::default()
    };

    // Create agent
    let agent = BotManagementAgent::new(config, &args.good_bots, &args.bad_patterns).await?;

    // Run agent with appropriate transport
    if let Some(grpc_addr) = args.grpc_address {
        // Use gRPC transport
        info!(
            address = %grpc_addr,
            "Starting bot-management agent with gRPC v2 transport"
        );

        let addr: std::net::SocketAddr = grpc_addr.parse()?;
        let server = GrpcAgentServerV2::new("bot-management", Box::new(agent));
        server.run(addr).await?;
    } else {
        // Use Unix Domain Socket transport
        info!(
            socket = %args.socket.display(),
            "Starting bot-management agent with UDS v2 transport"
        );

        let server = UdsAgentServerV2::new("bot-management", args.socket, Box::new(agent));
        server.run().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The release pipeline and `zentinel bundle install` expect exactly
    /// `<binary> <version>`.
    #[test]
    fn version_is_binary_name_and_package_version() {
        assert_eq!(
            Args::command().render_version(),
            format!("{} {}\n", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"))
        );
    }
}
