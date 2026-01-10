//! Configuration types for the Bot Management agent.

use serde::{Deserialize, Serialize};

/// Main configuration for the Bot Management agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BotManagementConfig {
    /// Score thresholds for decisions
    pub thresholds: ThresholdConfig,

    /// Detection settings
    pub detection: DetectionConfig,

    /// Known good bots to allow
    pub allow_list: AllowListConfig,

    /// Challenge settings
    pub challenge: ChallengeConfig,

    /// Behavioral analysis settings
    pub behavioral: BehavioralConfig,

    /// Cache settings
    pub cache: CacheConfig,

    /// Performance settings
    pub performance: PerformanceConfig,

    /// Include debug headers in response
    pub debug_headers: bool,
}

impl Default for BotManagementConfig {
    fn default() -> Self {
        Self {
            thresholds: ThresholdConfig::default(),
            detection: DetectionConfig::default(),
            allow_list: AllowListConfig::default(),
            challenge: ChallengeConfig::default(),
            behavioral: BehavioralConfig::default(),
            cache: CacheConfig::default(),
            performance: PerformanceConfig::default(),
            debug_headers: false,
        }
    }
}

/// Score thresholds for bot decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdConfig {
    /// Score below which to allow (0-100)
    pub allow_threshold: u8,

    /// Score above which to block (0-100)
    pub block_threshold: u8,

    /// Minimum confidence to act on score (0.0-1.0)
    pub min_confidence: f32,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            allow_threshold: 30,
            block_threshold: 80,
            min_confidence: 0.5,
        }
    }
}

/// Detection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// Enable header analysis
    pub header_analysis: bool,

    /// Enable user-agent validation
    pub user_agent_validation: bool,

    /// Enable known bot database lookup
    pub known_bot_lookup: bool,

    /// Enable behavioral analysis
    pub behavioral_analysis: bool,

    /// Signal weights for score calculation
    pub weights: SignalWeights,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            header_analysis: true,
            user_agent_validation: true,
            known_bot_lookup: true,
            behavioral_analysis: true,
            weights: SignalWeights::default(),
        }
    }
}

/// Weights for each signal in score calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalWeights {
    pub header: f32,
    pub user_agent: f32,
    pub known_bot: f32,
    pub behavioral: f32,
}

impl Default for SignalWeights {
    fn default() -> Self {
        Self {
            header: 0.20,
            user_agent: 0.25,
            known_bot: 0.35,
            behavioral: 0.20,
        }
    }
}

/// Allow list configuration for known good bots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowListConfig {
    /// Allow search engine crawlers (Google, Bing, etc.)
    pub search_engines: bool,

    /// Allow social media crawlers (Facebook, Twitter, etc.)
    pub social_media: bool,

    /// Allow monitoring services (Pingdom, UptimeRobot, etc.)
    pub monitoring: bool,

    /// Allow SEO tools (Ahrefs, Semrush, etc.)
    pub seo_tools: bool,

    /// Verify bot identity via reverse DNS
    pub verify_identity: bool,

    /// Custom allowed user-agent patterns
    pub custom_patterns: Vec<String>,

    /// Custom allowed IP ranges (CIDR notation)
    pub custom_ip_ranges: Vec<String>,
}

impl Default for AllowListConfig {
    fn default() -> Self {
        Self {
            search_engines: true,
            social_media: true,
            monitoring: true,
            seo_tools: false,
            verify_identity: true,
            custom_patterns: vec![],
            custom_ip_ranges: vec![],
        }
    }
}

/// Challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChallengeConfig {
    /// Default challenge type
    pub default_type: ChallengeType,

    /// Challenge page URL (for redirect challenges)
    pub challenge_url: Option<String>,

    /// JavaScript challenge script URL
    pub js_challenge_url: Option<String>,

    /// Challenge token validity in seconds
    pub token_validity_seconds: u64,

    /// Secret for HMAC token signing
    pub token_secret: String,

    /// Cookie name for challenge token
    pub cookie_name: String,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            default_type: ChallengeType::JavaScript,
            challenge_url: None,
            js_challenge_url: Some("/_sentinel/challenge.js".to_string()),
            token_validity_seconds: 300,
            token_secret: "change-me-in-production".to_string(),
            cookie_name: "_sentinel_bot_check".to_string(),
        }
    }
}

/// Challenge types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// JavaScript computation challenge
    JavaScript,
    /// CAPTCHA challenge
    Captcha,
    /// Proof of work challenge
    ProofOfWork,
}

impl Default for ChallengeType {
    fn default() -> Self {
        Self::JavaScript
    }
}

/// Behavioral analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BehavioralConfig {
    /// Maximum sessions to track
    pub max_sessions: usize,

    /// Session timeout in seconds
    pub session_timeout_seconds: u64,

    /// Requests per minute threshold
    pub rpm_threshold: u32,

    /// Minimum requests before behavioral scoring
    pub min_requests_for_scoring: u32,

    /// Maximum request history per session
    pub max_request_history: usize,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100_000,
            session_timeout_seconds: 3600,
            rpm_threshold: 60,
            min_requests_for_scoring: 5,
            max_request_history: 100,
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Bot verification cache size
    pub verification_cache_size: u64,

    /// Bot verification cache TTL in seconds
    pub verification_cache_ttl_seconds: u64,

    /// DNS lookup cache size
    pub dns_cache_size: u64,

    /// DNS lookup cache TTL in seconds
    pub dns_cache_ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            verification_cache_size: 10_000,
            verification_cache_ttl_seconds: 3600,
            dns_cache_size: 10_000,
            dns_cache_ttl_seconds: 3600,
        }
    }
}

/// Performance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    /// Maximum time for detection in milliseconds
    pub max_detection_time_ms: u64,

    /// Enable adaptive throttling under load
    pub adaptive_throttling: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_detection_time_ms: 50,
            adaptive_throttling: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BotManagementConfig::default();
        assert_eq!(config.thresholds.allow_threshold, 30);
        assert_eq!(config.thresholds.block_threshold, 80);
        assert!(config.detection.header_analysis);
        assert!(config.allow_list.search_engines);
    }

    #[test]
    fn test_config_serialization() {
        let config = BotManagementConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: BotManagementConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.thresholds.allow_threshold, config.thresholds.allow_threshold);
    }
}
