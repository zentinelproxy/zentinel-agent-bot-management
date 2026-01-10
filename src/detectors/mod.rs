//! Bot detection modules.
//!
//! Each detector analyzes a specific aspect of the request and returns a score.

pub mod behavioral;
pub mod headers;
pub mod known_bots;
pub mod user_agent;

pub use behavioral::BehavioralAnalyzer;
pub use headers::HeaderAnalyzer;
pub use known_bots::KnownBotDatabase;
pub use user_agent::UserAgentAnalyzer;

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;

/// Context for detection containing request information.
#[derive(Debug, Clone)]
pub struct DetectionContext {
    /// Request headers (lowercase keys)
    pub headers: HashMap<String, Vec<String>>,
    /// Client IP address
    pub client_ip: IpAddr,
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Correlation ID for the request
    pub correlation_id: String,
}

impl DetectionContext {
    /// Get a single header value (first if multiple).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Get the User-Agent header.
    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }
}

/// Result from a detector.
#[derive(Debug, Clone)]
pub struct DetectorResult {
    /// Score from this detector (0-100)
    pub score: u8,
    /// Reasons for the score
    pub reasons: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl DetectorResult {
    /// Create a new detector result.
    pub fn new(score: u8) -> Self {
        Self {
            score,
            reasons: vec![],
            metadata: HashMap::new(),
        }
    }

    /// Add a reason for the score.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Trait for bot detectors.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Analyze the request and return a detection result.
    async fn analyze(&self, ctx: &DetectionContext) -> DetectorResult;

    /// Get the detector name.
    fn name(&self) -> &'static str;
}
