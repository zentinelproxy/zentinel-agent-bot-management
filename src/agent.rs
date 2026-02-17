//! Main bot management agent implementation.

use crate::challenge::ChallengeManager;
use crate::config::BotManagementConfig;
use crate::detectors::{
    BehavioralAnalyzer, DetectionContext, Detector, HeaderAnalyzer, KnownBotDatabase,
    UserAgentAnalyzer,
};
use crate::score::{BotCategory, BotScore, ScoreCalculator, SignalBreakdown};
use async_trait::async_trait;
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, DrainReason, HealthStatus, MetricsReport,
    ShutdownReason, CounterMetric, GaugeMetric,
};
use zentinel_agent_protocol::{
    AgentResponse, Decision, EventType, RequestHeadersEvent,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Bot Management Agent for Zentinel.
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
    /// Metrics: total requests processed
    requests_total: AtomicU64,
    /// Metrics: requests blocked
    requests_blocked: AtomicU64,
    /// Metrics: requests challenged
    requests_challenged: AtomicU64,
    /// Metrics: requests allowed
    requests_allowed: AtomicU64,
    /// Metrics: verified good bots
    verified_good_bots: AtomicU64,
    /// Metrics: verified bad bots (fake bots)
    verified_bad_bots: AtomicU64,
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
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_challenged: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            verified_good_bots: AtomicU64::new(0),
            verified_bad_bots: AtomicU64::new(0),
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
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_challenged: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            verified_good_bots: AtomicU64::new(0),
            verified_bad_bots: AtomicU64::new(0),
        })
    }

    /// Build detection context from request headers event.
    fn build_context(&self, event: &RequestHeadersEvent) -> DetectionContext {
        let headers: HashMap<String, Vec<String>> = event
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let client_ip: IpAddr = event
            .metadata
            .client_ip
            .parse()
            .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

        DetectionContext {
            headers,
            client_ip,
            path: event.uri.clone(),
            method: event.method.clone(),
            correlation_id: event.metadata.correlation_id.clone(),
        }
    }

    /// Check if a valid challenge token is present in request headers.
    fn has_valid_challenge_token(&self, event: &RequestHeadersEvent) -> bool {
        if let Some(cookies) = event.headers.get("cookie").and_then(|v| v.first()) {
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
    fn make_decision(&self, score: &BotScore) -> AgentResponse {
        let thresholds = &self.config.thresholds;

        // Don't act if confidence is too low
        if score.confidence < thresholds.min_confidence && !score.is_verified {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            return self.add_bot_headers(AgentResponse::default_allow(), score);
        }

        if score.score <= thresholds.allow_threshold {
            // Allow - low bot score
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            self.add_bot_headers(AgentResponse::default_allow(), score)
        } else if score.score >= thresholds.block_threshold {
            // Block - high bot score
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            let mut block_headers = HashMap::new();
            block_headers.insert("Content-Type".to_string(), "application/json".to_string());
            let mut response = AgentResponse::block(
                403,
                Some(r#"{"error": "access_denied", "reason": "bot_detected"}"#.to_string()),
            );
            response.decision = Decision::Block {
                status: 403,
                body: Some(r#"{"error": "access_denied", "reason": "bot_detected"}"#.to_string()),
                headers: Some(block_headers),
            };
            self.add_bot_headers_to_response(&mut response, score);
            response
        } else {
            // Challenge - uncertain
            self.requests_challenged.fetch_add(1, Ordering::Relaxed);
            let params = self
                .challenge_manager
                .get_challenge_params(&self.config.challenge.default_type);
            let challenge_type = match self.config.challenge.default_type {
                crate::config::ChallengeType::JavaScript => "javascript",
                crate::config::ChallengeType::Captcha => "captcha",
                crate::config::ChallengeType::ProofOfWork => "proof_of_work",
            };
            let mut response = AgentResponse::default_allow();
            response.decision = Decision::Challenge {
                challenge_type: challenge_type.to_string(),
                params,
            };
            self.add_bot_headers_to_response(&mut response, score);
            response
        }
    }

    /// Add bot score headers to an AgentResponse.
    fn add_bot_headers(&self, mut response: AgentResponse, score: &BotScore) -> AgentResponse {
        self.add_bot_headers_to_response(&mut response, score);
        response
    }

    /// Add bot score headers to response (in place).
    fn add_bot_headers_to_response(&self, response: &mut AgentResponse, score: &BotScore) {
        use zentinel_agent_protocol::HeaderOp;

        // Add response headers
        response.response_headers.push(HeaderOp::Set {
            name: "X-Bot-Score".to_string(),
            value: score.score.to_string(),
        });
        response.response_headers.push(HeaderOp::Set {
            name: "X-Bot-Category".to_string(),
            value: score.category.as_str().to_string(),
        });
        response.response_headers.push(HeaderOp::Set {
            name: "X-Bot-Confidence".to_string(),
            value: format!("{:.2}", score.confidence),
        });

        if let Some(ref name) = score.verified_bot_name {
            response.response_headers.push(HeaderOp::Set {
                name: "X-Bot-Verified".to_string(),
                value: name.clone(),
            });
        }

        if self.config.debug_headers {
            if let Ok(signals_json) = serde_json::to_string(&score.signals) {
                response.response_headers.push(HeaderOp::Set {
                    name: "X-Bot-Signals".to_string(),
                    value: signals_json,
                });
            }
        }

        // Add audit metadata
        response.audit.tags.push("bot-management".to_string());
        response.audit.confidence = Some(score.confidence);
        response.audit.custom.insert(
            "bot_score".to_string(),
            serde_json::json!(score.score),
        );
        response.audit.custom.insert(
            "bot_category".to_string(),
            serde_json::json!(score.category.as_str()),
        );

        for reason in &score.signals.reasons {
            response.audit.reason_codes.push(reason.clone());
        }
    }
}

#[async_trait]
impl AgentHandlerV2 for BotManagementAgent {
    /// Return agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("bot-management", "Bot Management Agent", env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
            .with_features(AgentFeatures {
                streaming_body: false,
                websocket: false,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            })
    }

    /// Handle request headers event - main bot detection logic.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Check for valid challenge token first
        if self.has_valid_challenge_token(&event) {
            debug!(
                correlation_id = %event.metadata.correlation_id,
                "Valid challenge token found, allowing request"
            );
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
            let mut response = AgentResponse::default_allow();
            response.response_headers.push(zentinel_agent_protocol::HeaderOp::Set {
                name: "X-Bot-Challenge".to_string(),
                value: "passed".to_string(),
            });
            response.audit.tags.push("challenge_passed".to_string());
            return response;
        }

        // Build detection context
        let ctx = self.build_context(&event);

        // Run detection
        let score = self.detect(&ctx).await;

        // Track verified bot metrics
        if score.is_verified {
            if score.verified_bot_name.is_some() {
                self.verified_good_bots.fetch_add(1, Ordering::Relaxed);
            } else if score.score == 100 {
                self.verified_bad_bots.fetch_add(1, Ordering::Relaxed);
            }
        }

        info!(
            correlation_id = %event.metadata.correlation_id,
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

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("bot-management")
    }

    /// Return current metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("bot-management", 60_000);

        // Add counter metrics
        report.counters.push(CounterMetric::new(
            "bot_management_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "bot_management_requests_allowed",
            self.requests_allowed.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "bot_management_requests_blocked",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "bot_management_requests_challenged",
            self.requests_challenged.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "bot_management_verified_good_bots",
            self.verified_good_bots.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "bot_management_verified_bad_bots",
            self.verified_bad_bots.load(Ordering::Relaxed),
        ));

        // Add gauge metrics
        report.gauges.push(GaugeMetric::new(
            "bot_management_block_threshold",
            self.config.thresholds.block_threshold as f64,
        ));
        report.gauges.push(GaugeMetric::new(
            "bot_management_allow_threshold",
            self.config.thresholds.allow_threshold as f64,
        ));

        Some(report)
    }

    /// Handle configuration update from proxy.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            version = ?version,
            "Received configuration update"
        );

        // For now, we accept the config but don't apply it dynamically
        // A full implementation would validate and apply the new config
        if let Err(e) = serde_json::from_value::<BotManagementConfig>(config) {
            warn!(error = %e, "Invalid configuration received, rejecting");
            return false;
        }

        true
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Shutdown requested"
        );
        // Perform any cleanup if needed
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Drain requested"
        );
        // Stop accepting new requests if needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_agent_protocol::RequestMetadata;

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
        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "bot-management");
        assert_eq!(caps.name, "Bot Management Agent");
    }

    #[tokio::test]
    async fn test_detection_context_building() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        let event = make_request_event(
            "Mozilla/5.0 Chrome/120",
            "192.168.1.100",
            "/test",
        );
        let ctx = agent.build_context(&event);

        assert_eq!(ctx.client_ip.to_string(), "192.168.1.100");
        assert_eq!(ctx.path, "/test");
        assert!(ctx.headers.contains_key("user-agent"));
    }

    #[tokio::test]
    async fn test_capabilities() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        let caps = agent.capabilities();

        assert!(caps.features.config_push);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
        assert!(!caps.features.streaming_body);
        assert!(caps.supports_event(EventType::RequestHeaders));
    }

    #[tokio::test]
    async fn test_health_status() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        let health = agent.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "bot-management");
    }

    #[tokio::test]
    async fn test_metrics_report() {
        let agent = BotManagementAgent::with_defaults().await.unwrap();
        let report = agent.metrics_report();

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "bot-management");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }
}
