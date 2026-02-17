//! Bot Management Agent for Zentinel
//!
//! Detects bots through multiple signals and returns bot scores.

use anyhow::Result;
use clap::Parser;
use zentinel_agent_bot_management::{BotManagementAgent, BotManagementConfig};
use zentinel_agent_protocol::v2::GrpcAgentServerV2;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "zentinel-agent-bot-management")]
#[command(author, version, about = "Bot detection and management agent for Zentinel")]
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

    let env_filter = EnvFilter::from_default_env()
        .add_directive(level.into());

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
        if config_path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
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

        // For UDS, we need to implement a UDS server or use the existing infrastructure
        // For now, we'll create a simple UDS server using the agent protocol
        run_uds_server(args.socket, agent).await?;
    }

    Ok(())
}

/// Run the agent as a UDS server.
async fn run_uds_server(socket_path: PathBuf, agent: BotManagementAgent) -> Result<()> {
    use zentinel_agent_protocol::v2::uds::{
        read_message, write_message, MessageType, UdsHandshakeRequest, UdsHandshakeResponse,
        UdsCapabilities, UdsFeatures, UdsLimits,
    };
    use zentinel_agent_protocol::v2::AgentHandlerV2;
    use tokio::io::{BufReader, BufWriter};
    use tokio::net::UnixListener;
    use std::sync::Arc;

    // Remove existing socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!(socket = %socket_path.display(), "UDS v2 server listening");

    let agent = Arc::new(agent);

    loop {
        let (stream, _) = listener.accept().await?;
        let agent = Arc::clone(&agent);

        tokio::spawn(async move {
            let (read_half, write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut writer = BufWriter::new(write_half);

            // Perform handshake
            let (msg_type, payload) = match read_message(&mut reader).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read handshake request");
                    return;
                }
            };

            if msg_type != MessageType::HandshakeRequest {
                tracing::error!(?msg_type, "Expected handshake request");
                return;
            }

            let _handshake_req: UdsHandshakeRequest = match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse handshake request");
                    return;
                }
            };

            // Build handshake response with capabilities
            let caps = agent.capabilities();
            let response = UdsHandshakeResponse {
                protocol_version: 2,
                capabilities: UdsCapabilities {
                    agent_id: caps.agent_id.clone(),
                    name: caps.name.clone(),
                    version: caps.version.clone(),
                    supported_events: vec![1], // RequestHeaders
                    features: UdsFeatures {
                        streaming_body: caps.features.streaming_body,
                        websocket: caps.features.websocket,
                        guardrails: caps.features.guardrails,
                        config_push: caps.features.config_push,
                        metrics_export: caps.features.metrics_export,
                        concurrent_requests: caps.features.concurrent_requests,
                        cancellation: caps.features.cancellation,
                        flow_control: caps.features.flow_control,
                        health_reporting: caps.features.health_reporting,
                    },
                    limits: UdsLimits {
                        max_body_size: caps.limits.max_body_size as u64,
                        max_concurrency: caps.limits.max_concurrency,
                        preferred_chunk_size: caps.limits.preferred_chunk_size as u64,
                    },
                },
                success: true,
                error: None,
                encoding: zentinel_agent_protocol::v2::uds::UdsEncoding::Json,
            };

            let response_bytes = match serde_json::to_vec(&response) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to serialize handshake response");
                    return;
                }
            };

            if let Err(e) = write_message(&mut writer, MessageType::HandshakeResponse, &response_bytes).await {
                tracing::error!(error = %e, "Failed to write handshake response");
                return;
            }

            info!("UDS v2 handshake complete");

            // Process events
            loop {
                let (msg_type, payload) = match read_message(&mut reader).await {
                    Ok(r) => r,
                    Err(zentinel_agent_protocol::AgentProtocolError::ConnectionClosed) => {
                        tracing::debug!("Client disconnected");
                        break;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to read message");
                        break;
                    }
                };

                match msg_type {
                    MessageType::RequestHeaders => {
                        let event: zentinel_agent_protocol::RequestHeadersEvent =
                            match serde_json::from_slice(&payload) {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::error!(error = %e, "Failed to parse request headers event");
                                    continue;
                                }
                            };

                        let response = agent.on_request_headers(event).await;

                        let response_bytes = match serde_json::to_vec(&response) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to serialize response");
                                continue;
                            }
                        };

                        if let Err(e) = write_message(&mut writer, MessageType::AgentResponse, &response_bytes).await {
                            tracing::error!(error = %e, "Failed to write response");
                            break;
                        }
                    }
                    MessageType::HealthStatus => {
                        let health = agent.health_status();
                        let health_bytes = match serde_json::to_vec(&health) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to serialize health status");
                                continue;
                            }
                        };

                        if let Err(e) = write_message(&mut writer, MessageType::HealthStatus, &health_bytes).await {
                            tracing::error!(error = %e, "Failed to write health status");
                            break;
                        }
                    }
                    MessageType::MetricsReport => {
                        if let Some(report) = agent.metrics_report() {
                            let report_bytes = match serde_json::to_vec(&report) {
                                Ok(b) => b,
                                Err(e) => {
                                    tracing::error!(error = %e, "Failed to serialize metrics report");
                                    continue;
                                }
                            };

                            if let Err(e) = write_message(&mut writer, MessageType::MetricsReport, &report_bytes).await {
                                tracing::error!(error = %e, "Failed to write metrics report");
                                break;
                            }
                        }
                    }
                    MessageType::Configure => {
                        #[derive(serde::Deserialize)]
                        struct ConfigureMsg {
                            config: serde_json::Value,
                            version: Option<String>,
                        }

                        if let Ok(config_msg) = serde_json::from_slice::<ConfigureMsg>(&payload) {
                            let accepted = agent.on_configure(config_msg.config, config_msg.version).await;
                            tracing::info!(accepted = accepted, "Configuration update processed");
                        }
                    }
                    MessageType::Ping => {
                        // Echo back as pong
                        if let Err(e) = write_message(&mut writer, MessageType::Pong, &payload).await {
                            tracing::error!(error = %e, "Failed to write pong");
                            break;
                        }
                    }
                    _ => {
                        tracing::debug!(?msg_type, "Unhandled message type");
                    }
                }
            }
        });
    }
}
