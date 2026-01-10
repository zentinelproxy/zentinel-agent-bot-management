//! Bot Management Agent for Sentinel
//!
//! Detects bots through multiple signals and returns bot scores.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_bot_management::{BotManagementAgent, BotManagementConfig};
use sentinel_agent_sdk::AgentRunner;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-bot-management")]
#[command(author, version, about = "Bot detection and management agent for Sentinel")]
struct Args {
    /// Unix socket path for the agent server
    #[arg(short, long, default_value = "/tmp/sentinel-bot-management.sock")]
    socket: PathBuf,

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        let content = std::fs::read_to_string(config_path)?;
        if config_path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        }
    } else {
        BotManagementConfig::default()
    };

    // Create agent
    let agent = BotManagementAgent::new(config, &args.good_bots, &args.bad_patterns).await?;

    // Run agent
    let mut runner = AgentRunner::new(agent)
        .with_name("bot-management")
        .with_socket(&args.socket);

    if args.json_logs {
        runner = runner.with_json_logs();
    }

    runner.run().await
}
