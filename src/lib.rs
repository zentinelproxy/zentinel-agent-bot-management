//! Bot Management Agent for Zentinel
//!
//! Detects bots through multiple signals and returns bot scores with
//! ALLOW/BLOCK/CHALLENGE decisions.
//!
//! # Features
//!
//! - Header analysis (order, presence, consistency)
//! - User-Agent parsing and validation
//! - Known good/bad bot database with verification
//! - Behavioral analysis (request patterns, timing)
//! - Challenge token system for suspicious traffic
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_bot_management::BotManagementAgent;
//! use zentinel_agent_sdk::AgentRunner;
//!
//! let agent = BotManagementAgent::new(config);
//! AgentRunner::new(agent)
//!     .with_socket("/tmp/bot-management.sock")
//!     .run()
//!     .await?;
//! ```

pub mod agent;
pub mod cache;
pub mod challenge;
pub mod config;
pub mod detectors;
pub mod score;

pub use agent::BotManagementAgent;
pub use config::BotManagementConfig;
pub use score::{BotCategory, BotScore, SignalBreakdown};
