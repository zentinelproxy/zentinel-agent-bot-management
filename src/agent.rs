//! Main bot management agent implementation.

use crate::challenge::ChallengeManager;
use crate::config::BotManagementConfig;
use crate::detectors::{
    BehavioralAnalyzer, DetectionContext, Detector, HeaderAnalyzer, KnownBotDatabase,
    UserAgentAnalyzer,
};
use crate::score::{BotCategory, BotScore, ScoreCalculator, SignalBreakdown};
use async_trait::async_trait;
use sentinel_agent_sdk::Agent;
use sentinel_agent_sdk::Decision;
use sentinel_agent_sdk::Request;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Bot Management Agent for Sentinel.
pub struct BotManagementAgent {
    /// Configuration
    config: BotManagementConfig,
    /// Header analyzer
    header_analyzer: HeaderAnalyzer,
    /// User-Agent analyzer
    user_agent_analyzer: UserAgentAnalyzer,
    /// Known bot database
    known_bot_db: Arc<KnownBotDatabase>,
    /// Behavioral analyzer
    behavioral_analyzer: BehavioralAnalyzer,
    /// Score calculator
    score_calculator: ScoreCalculator,
    /// Challenge manager
    challenge_manager: ChallengeManager,
}

impl BotManagementAgent {
    /// Create a new bot management agent.
    pub async fn new(
        config: BotManagementConfig,
        good_bots_path: &Path,
        bad_patterns_path: &Path,
    ) -> anyhow::Result<Self> {
        // Create known bot database
        let known_bot_db = KnownBotDatabase::new(
            good_bots_path,
            bad_patterns_path,
            config.allow_list.verify_identity,
            config.cache.verification_cache_size,
            Duration::from_secs(config.cache.verification_cache_ttl_seconds),
        )
        .await?;

        // Create behavioral analyzer
        let behavioral_analyzer = BehavioralAnalyzer::new(
            config.behavioral.max_sessions,
            Duration::from_secs(config.behavioral.session_timeout_seconds),
            config.behavioral.rpm_threshold,
            config.behavioral.min_requests_for_scoring,
            config.behavioral.max_request_history,
        );

        // Create score calculator
        let score_calculator = ScoreCalculator::new(
            config.detection.weights.header,
            config.detection.weights.user_agent,
            config.detection.weights.known_bot,
            config.detection.weights.behavioral,
        );

        // Create challenge manager
        let challenge_manager = ChallengeManager::new(
            &config.challenge.token_secret,
            config.challenge.token_validity_seconds,
            &config.challenge.cookie_name,
            config.challenge.default_type.clone(),
            config.challenge.js_challenge_url.clone(),
            config.challenge.challenge_url.clone(),
        );

        Ok(Self {
            config,
            header_analyzer: HeaderAnalyzer::new(),
            user_agent_analyzer: UserAgentAnalyzer::new(),
            known_bot_db: Arc::new(known_bot_db),
            behavioral_analyzer,
            score_calculator,
            challenge_manager,
        })
    }

    /// Create with default configuration.
    pub async fn with_defaults() -> anyhow::Result<Self> {
        let config = BotManagementConfig::default();
        let known_bot_db = KnownBotDatabase::with_defaults(config.allow_list.verify_identity).await?;

        let behavioral_analyzer = BehavioralAnalyzer::new(
            config.behavioral.max_sessions,
            Duration::from_secs(config.behavioral.session_timeout_seconds),
            config.behavioral.rpm_threshold,
            config.behavioral.min_requests_for_scoring,
            config.behavioral.max_request_history,
        );

        let score_calculator = ScoreCalculator::default();

        let challenge_manager = ChallengeManager::new(
            &config.challenge.token_secret,
            config.challenge.token_validity_seconds,
            &config.challenge.cookie_name,
            config.challenge.default_type.clone(),
            config.challenge.js_challenge_url.clone(),
            config.challenge.challenge_url.clone(),
        );

        Ok(Self {
            config,
            header_analyzer: HeaderAnalyzer::new(),
            user_agent_analyzer: UserAgentAnalyzer::new(),
            known_bot_db: Arc::new(known_bot_db),
            behavioral_analyzer,
            score_calculator,
            challenge_manager,
        })
    }

    /// Build detection context from request.
    fn build_context(&self, request: &Request) -> DetectionContext {
        let headers: HashMap<String, Vec<String>> = request
            .headers()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let client_ip: IpAddr = request
            .client_ip()
            .parse()
            .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

        DetectionContext {
            headers,
            client_ip,
            path: request.path().to_string(),
            method: request.method().to_string(),
            correlation_id: request.correlation_id().to_string(),
        }
    }

    /// Check if a valid challenge token is present.
    fn has_valid_challenge_token(&self, request: &Request) -> bool {
        if let Some(cookies) = request.header("cookie") {
            if let Some(token) = self.challenge_manager.extract_token_from_cookies(cookies) {
                return self.challenge_manager.verify_token(&token);
            }
        }
        false
    }

    /// Run all detectors and calculate bot score.
    async fn detect(&self, ctx: &DetectionContext) -> BotScore {
        let mut signals = SignalBreakdown::default();

        // Run detectors based on configuration
        if self.config.detection.header_analysis {
            let result = self.header_analyzer.analyze(ctx).await;
            signals.header_score = Some(result.score);
            signals.reasons.extend(result.reasons);
            debug!(
                detector = "headers",
                score = result.score,
                "Header analysis complete"
            );
        }

        if self.config.detection.user_agent_validation {
            let result = self.user_agent_analyzer.analyze(ctx).await;
            signals.user_agent_score = Some(result.score);
            signals.reasons.extend(result.reasons);
            debug!(
                detector = "user_agent",
                score = result.score,
                "User-Agent analysis complete"
            );
        }

        if self.config.detection.known_bot_lookup {
            let result = self.known_bot_db.analyze(ctx).await;
            signals.known_bot_score = Some(result.score);
            signals.reasons.extend(result.reasons);

            // Check if this is a verified bot
            if result.score == 0 {
                if let Some(bot_name) = result.metadata.get("verified_bot") {
                    // This is a verified good bot - return immediately
                    let category = self.category_from_signals(&signals);
                    return BotScore::verified_good_bot(bot_name, category);
                }
            } else if result.score == 100 {
                // This is a fake/bad bot - return immediately
                let reason = signals.reasons.last().cloned().unwrap_or_default();
                return BotScore::verified_bad_bot(reason);
            }

            debug!(
                detector = "known_bots",
                score = result.score,
                "Known bot lookup complete"
            );
        }

        if self.config.detection.behavioral_analysis {
            let result = self.behavioral_analyzer.analyze(ctx).await;
            signals.behavioral_score = Some(result.score);
            signals.reasons.extend(result.reasons);
            debug!(
                detector = "behavioral",
                score = result.score,
                "Behavioral analysis complete"
            );
        }

        // Calculate final score
        self.score_calculator.calculate(&signals)
    }

    fn category_from_signals(&self, _signals: &SignalBreakdown) -> BotCategory {
        // Default to SearchEngine for verified bots
        BotCategory::SearchEngine
    }

    /// Make decision based on bot score.
    fn make_decision(&self, score: &BotScore) -> Decision {
        let thresholds = &self.config.thresholds;

        // Don't act if confidence is too low
        if score.confidence < thresholds.min_confidence && !score.is_verified {
            return self.add_bot_headers(Decision::allow(), score);
        }

        if score.score <= thresholds.allow_threshold {
            // Allow - low bot score
            self.add_bot_headers(Decision::allow(), score)
        } else if score.score >= thresholds.block_threshold {
            // Block - high bot score
            self.add_bot_headers(
                Decision::deny()
                    .with_body(r#"{"error": "access_denied", "reason": "bot_detected"}"#)
                    .with_block_header("Content-Type", "application/json"),
                score,
            )
        } else {
            // Challenge - uncertain
            let params = self
                .challenge_manager
                .get_challenge_params(&self.config.challenge.default_type);
            let challenge_type = match self.config.challenge.default_type {
                crate::config::ChallengeType::JavaScript => "javascript",
                crate::config::ChallengeType::Captcha => "captcha",
                crate::config::ChallengeType::ProofOfWork => "proof_of_work",
            };
            self.add_bot_headers(Decision::challenge(challenge_type, params), score)
        }
    }

    /// Add bot score headers to decision.
    fn add_bot_headers(&self, decision: Decision, score: &BotScore) -> Decision {
        let mut d = decision
            .add_response_header("X-Bot-Score", score.score.to_string())
            .add_response_header("X-Bot-Category", score.category.as_str())
            .add_response_header("X-Bot-Confidence", format!("{:.2}", score.confidence));

        if let Some(ref name) = score.verified_bot_name {
            d = d.add_response_header("X-Bot-Verified", name.clone());
        }

        if self.config.debug_headers {
            if let Ok(signals_json) = serde_json::to_string(&score.signals) {
                d = d.add_response_header("X-Bot-Signals", signals_json);
            }
        }

        // Add audit metadata
        d = d
            .with_tag("bot-management")
            .with_confidence(score.confidence)
            .with_metadata("bot_score", serde_json::json!(score.score))
            .with_metadata("bot_category", serde_json::json!(score.category.as_str()));

        for reason in &score.signals.reasons {
            d = d.with_reason_code(reason.clone());
        }

        d
    }
}

#[async_trait]
impl Agent for BotManagementAgent {
    fn name(&self) -> &str {
        "bot-management"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Check for valid challenge token first
        if self.has_valid_challenge_token(request) {
            debug!(
                correlation_id = request.correlation_id(),
                "Valid challenge token found, allowing request"
            );
            return Decision::allow()
                .add_response_header("X-Bot-Challenge", "passed")
                .with_tag("challenge_passed");
        }

        // Build detection context
        let ctx = self.build_context(request);

        // Run detection
        let score = self.detect(&ctx).await;

        info!(
            correlation_id = request.correlation_id(),
            client_ip = %ctx.client_ip,
            path = %ctx.path,
            bot_score = score.score,
            confidence = score.confidence,
            category = %score.category.as_str(),
            verified = score.is_verified,
            "Bot detection complete"
        );

        // Make decision
        self.make_decision(&score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_agent_protocol::{RequestHeadersEvent, RequestMetadata};

    fn make_request_event(ua: &str, ip: &str, path: &str) -> RequestHeadersEvent {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), vec![ua.to_string()]);
        headers.insert("accept".to_string(), vec!["text/html".to_string()]);
        headers.insert("accept-language".to_string(), vec!["en-US".to_string()]);
        headers.insert("accept-encoding".to_string(), vec!["gzip".to_string()]);

        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: ip.to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: path.to_string(),
            headers,
        }
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        assert_eq!(agent.name(), "bot-management");
    }

    #[tokio::test]
    async fn test_detection_context_building() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        let event = make_request_event(
            "Mozilla/5.0 Chrome/120",
            "192.168.1.100",
            "/test",
        );
        let request = Request::from_headers_event(&event);
        let ctx = agent.build_context(&request);

        assert_eq!(ctx.client_ip.to_string(), "192.168.1.100");
        assert_eq!(ctx.path, "/test");
        assert!(ctx.headers.contains_key("user-agent"));
    }
}
