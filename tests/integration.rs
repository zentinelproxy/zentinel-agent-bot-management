//! Integration tests for the Sentinel Bot Management Agent.
//!
//! These tests verify the complete functionality of the bot management agent,
//! including configuration parsing, bot scoring, challenge tokens, and detectors.

use sentinel_agent_bot_management::{
    BotManagementAgent, BotManagementConfig, BotCategory, BotScore, SignalBreakdown,
};
use sentinel_agent_bot_management::config::{
    AllowListConfig, BehavioralConfig, CacheConfig, ChallengeConfig, ChallengeType,
    DetectionConfig, PerformanceConfig, SignalWeights, ThresholdConfig,
};
use sentinel_agent_bot_management::score::ScoreCalculator;
use sentinel_agent_bot_management::challenge::ChallengeManager;
use sentinel_agent_bot_management::detectors::{
    DetectionContext, DetectorResult, Detector,
    UserAgentAnalyzer, HeaderAnalyzer,
};
use std::collections::HashMap;

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_default_config_is_valid() {
    let config = BotManagementConfig::default();

    assert_eq!(config.thresholds.allow_threshold, 30);
    assert_eq!(config.thresholds.block_threshold, 80);
    assert!((config.thresholds.min_confidence - 0.5).abs() < f32::EPSILON);

    assert!(config.detection.header_analysis);
    assert!(config.detection.user_agent_validation);
    assert!(config.detection.known_bot_lookup);
    assert!(config.detection.behavioral_analysis);

    assert!(config.allow_list.search_engines);
    assert!(config.allow_list.verify_identity);

    assert_eq!(config.challenge.default_type, ChallengeType::JavaScript);
}

#[test]
fn test_config_from_json() {
    let json = r#"{
        "thresholds": {
            "allow_threshold": 25,
            "block_threshold": 75,
            "min_confidence": 0.6
        },
        "detection": {
            "header_analysis": true,
            "user_agent_validation": true,
            "known_bot_lookup": false,
            "behavioral_analysis": false
        },
        "allow_list": {
            "search_engines": true,
            "social_media": false,
            "monitoring": true,
            "seo_tools": false,
            "verify_identity": true
        },
        "debug_headers": true
    }"#;

    let config: BotManagementConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.thresholds.allow_threshold, 25);
    assert_eq!(config.thresholds.block_threshold, 75);
    assert!(!config.detection.known_bot_lookup);
    assert!(!config.detection.behavioral_analysis);
    assert!(!config.allow_list.social_media);
    assert!(config.debug_headers);
}

#[test]
fn test_threshold_config() {
    let config = ThresholdConfig {
        allow_threshold: 20,
        block_threshold: 90,
        min_confidence: 0.7,
    };

    assert_eq!(config.allow_threshold, 20);
    assert_eq!(config.block_threshold, 90);
}

#[test]
fn test_signal_weights_default() {
    let weights = SignalWeights::default();

    // Weights should sum to 1.0
    let sum = weights.header + weights.user_agent + weights.known_bot + weights.behavioral;
    assert!((sum - 1.0).abs() < 0.001);

    // Known bot should have highest weight
    assert!(weights.known_bot >= weights.header);
    assert!(weights.known_bot >= weights.behavioral);
}

#[test]
fn test_challenge_config() {
    let config = ChallengeConfig {
        default_type: ChallengeType::Captcha,
        challenge_url: Some("/captcha".to_string()),
        js_challenge_url: None,
        token_validity_seconds: 600,
        token_secret: "test-secret".to_string(),
        cookie_name: "_bot_check".to_string(),
    };

    assert_eq!(config.default_type, ChallengeType::Captcha);
    assert_eq!(config.token_validity_seconds, 600);
    assert_eq!(config.cookie_name, "_bot_check");
}

#[test]
fn test_behavioral_config() {
    let config = BehavioralConfig::default();

    assert_eq!(config.max_sessions, 100_000);
    assert_eq!(config.session_timeout_seconds, 3600);
    assert_eq!(config.rpm_threshold, 60);
    assert_eq!(config.min_requests_for_scoring, 5);
}

#[test]
fn test_cache_config() {
    let config = CacheConfig::default();

    assert_eq!(config.verification_cache_size, 10_000);
    assert_eq!(config.verification_cache_ttl_seconds, 3600);
    assert_eq!(config.dns_cache_size, 10_000);
}

#[test]
fn test_performance_config() {
    let config = PerformanceConfig::default();

    assert_eq!(config.max_detection_time_ms, 50);
    assert!(config.adaptive_throttling);
}

#[test]
fn test_allow_list_config() {
    let config = AllowListConfig {
        search_engines: true,
        social_media: true,
        monitoring: true,
        seo_tools: false,
        verify_identity: true,
        custom_patterns: vec!["my-bot/*".to_string()],
        custom_ip_ranges: vec!["10.0.0.0/8".to_string()],
    };

    assert!(config.search_engines);
    assert!(!config.seo_tools);
    assert_eq!(config.custom_patterns.len(), 1);
    assert_eq!(config.custom_ip_ranges.len(), 1);
}

// =============================================================================
// Bot Category Tests
// =============================================================================

#[test]
fn test_bot_category_is_good_bot() {
    assert!(BotCategory::SearchEngine.is_good_bot());
    assert!(BotCategory::SocialMedia.is_good_bot());
    assert!(BotCategory::Monitoring.is_good_bot());

    assert!(!BotCategory::Human.is_good_bot());
    assert!(!BotCategory::Malicious.is_good_bot());
    assert!(!BotCategory::Automation.is_good_bot());
    assert!(!BotCategory::HeadlessBrowser.is_good_bot());
}

#[test]
fn test_bot_category_is_malicious() {
    assert!(BotCategory::Malicious.is_malicious());
    assert!(BotCategory::SecurityScanner.is_malicious());

    assert!(!BotCategory::Human.is_malicious());
    assert!(!BotCategory::SearchEngine.is_malicious());
    assert!(!BotCategory::Automation.is_malicious());
}

#[test]
fn test_bot_category_as_str() {
    assert_eq!(BotCategory::Human.as_str(), "human");
    assert_eq!(BotCategory::SearchEngine.as_str(), "search_engine");
    assert_eq!(BotCategory::SocialMedia.as_str(), "social_media");
    assert_eq!(BotCategory::Monitoring.as_str(), "monitoring");
    assert_eq!(BotCategory::SeoTool.as_str(), "seo_tool");
    assert_eq!(BotCategory::SecurityScanner.as_str(), "security_scanner");
    assert_eq!(BotCategory::Malicious.as_str(), "malicious");
    assert_eq!(BotCategory::Automation.as_str(), "automation");
    assert_eq!(BotCategory::HeadlessBrowser.as_str(), "headless_browser");
    assert_eq!(BotCategory::Unknown.as_str(), "unknown");
}

// =============================================================================
// Bot Score Tests
// =============================================================================

#[test]
fn test_bot_score_default() {
    let score = BotScore::default();

    assert_eq!(score.score, 50);
    assert_eq!(score.confidence, 0.0);
    assert_eq!(score.category, BotCategory::Unknown);
    assert!(!score.is_verified);
    assert!(score.verified_bot_name.is_none());
}

#[test]
fn test_bot_score_new() {
    let score = BotScore::new(75, 0.8, BotCategory::Automation);

    assert_eq!(score.score, 75);
    assert!((score.confidence - 0.8).abs() < f32::EPSILON);
    assert_eq!(score.category, BotCategory::Automation);
}

#[test]
fn test_bot_score_verified_good_bot() {
    let score = BotScore::verified_good_bot("Googlebot", BotCategory::SearchEngine);

    assert_eq!(score.score, 0);
    assert_eq!(score.confidence, 1.0);
    assert!(score.is_verified);
    assert_eq!(score.verified_bot_name, Some("Googlebot".to_string()));
    assert_eq!(score.category, BotCategory::SearchEngine);
}

#[test]
fn test_bot_score_verified_bad_bot() {
    let score = BotScore::verified_bad_bot("Fake Googlebot - IP not from Google");

    assert_eq!(score.score, 100);
    assert_eq!(score.confidence, 1.0);
    assert!(score.is_verified);
    assert_eq!(score.category, BotCategory::Malicious);
    assert!(score.signals.reasons.contains(&"Fake Googlebot - IP not from Google".to_string()));
}

#[test]
fn test_bot_score_likely_human() {
    let score = BotScore::likely_human();

    assert_eq!(score.score, 10);
    assert!((score.confidence - 0.7).abs() < f32::EPSILON);
    assert_eq!(score.category, BotCategory::Human);
}

#[test]
fn test_bot_score_with_signals() {
    let signals = SignalBreakdown {
        header_score: Some(20),
        user_agent_score: Some(30),
        known_bot_score: None,
        behavioral_score: Some(40),
        reasons: vec!["test_reason".to_string()],
    };

    let score = BotScore::new(30, 0.6, BotCategory::Unknown)
        .with_signals(signals);

    assert_eq!(score.signals.header_score, Some(20));
    assert_eq!(score.signals.user_agent_score, Some(30));
    assert!(score.signals.reasons.contains(&"test_reason".to_string()));
}

#[test]
fn test_bot_score_with_reason() {
    let score = BotScore::new(50, 0.5, BotCategory::Unknown)
        .with_reason("suspicious_pattern");

    assert!(score.signals.reasons.contains(&"suspicious_pattern".to_string()));
}

// =============================================================================
// Score Calculator Tests
// =============================================================================

#[test]
fn test_score_calculator_no_signals() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown::default();
    let score = calc.calculate(&signals);

    assert_eq!(score.score, 50);
    assert_eq!(score.confidence, 0.0);
}

#[test]
fn test_score_calculator_all_low_signals() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(10),
        user_agent_score: Some(10),
        known_bot_score: Some(10),
        behavioral_score: Some(10),
        reasons: vec![],
    };
    let score = calc.calculate(&signals);

    assert_eq!(score.score, 10);
    assert!(score.confidence > 0.9);
    assert_eq!(score.category, BotCategory::Human);
}

#[test]
fn test_score_calculator_all_high_signals() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(90),
        user_agent_score: Some(90),
        known_bot_score: Some(90),
        behavioral_score: Some(90),
        reasons: vec![],
    };
    let score = calc.calculate(&signals);

    assert_eq!(score.score, 90);
    assert!(score.confidence > 0.9);
    assert_eq!(score.category, BotCategory::Malicious);
}

#[test]
fn test_score_calculator_mixed_signals() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(20),
        user_agent_score: Some(80),
        known_bot_score: Some(40),
        behavioral_score: Some(60),
        reasons: vec![],
    };
    let score = calc.calculate(&signals);

    // Weighted average should be somewhere in the middle
    assert!(score.score > 30 && score.score < 70);
}

#[test]
fn test_score_calculator_partial_signals() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(30),
        user_agent_score: None,
        known_bot_score: Some(70),
        behavioral_score: None,
        reasons: vec![],
    };
    let score = calc.calculate(&signals);

    // Should calculate based only on available signals
    assert!(score.score > 30 && score.score < 70);
    // Confidence should be reduced
    assert!(score.confidence < 0.7);
}

#[test]
fn test_score_calculator_custom_weights() {
    let calc = ScoreCalculator::new(0.1, 0.1, 0.7, 0.1);
    let signals = SignalBreakdown {
        header_score: Some(10),
        user_agent_score: Some(10),
        known_bot_score: Some(90),
        behavioral_score: Some(10),
        reasons: vec![],
    };
    let score = calc.calculate(&signals);

    // Weighted average: (10*0.1 + 10*0.1 + 90*0.7 + 10*0.1) / 1.0 = 66
    // Known bot pulls the average up significantly from other low scores
    assert!(score.score > 60 && score.score < 75);
}

#[test]
fn test_score_calculator_headless_detection() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(60),
        user_agent_score: Some(60),
        known_bot_score: None,
        behavioral_score: None,
        reasons: vec!["headless_browser_detected".to_string()],
    };
    let score = calc.calculate(&signals);

    assert_eq!(score.category, BotCategory::HeadlessBrowser);
}

#[test]
fn test_score_calculator_automation_detection() {
    let calc = ScoreCalculator::default();
    let signals = SignalBreakdown {
        header_score: Some(50),
        user_agent_score: Some(50),
        known_bot_score: None,
        behavioral_score: None,
        reasons: vec!["curl_detected".to_string()],
    };
    let score = calc.calculate(&signals);

    assert_eq!(score.category, BotCategory::Automation);
}

// =============================================================================
// Challenge Manager Tests
// =============================================================================

#[test]
fn test_challenge_manager_token_generation() {
    let manager = ChallengeManager::default();
    let token = manager.generate_token();

    assert!(!token.is_empty());
    let parts: Vec<&str> = token.split('|').collect();
    assert_eq!(parts.len(), 3);

    // First part should be a timestamp (numeric)
    assert!(parts[0].parse::<u64>().is_ok());
}

#[test]
fn test_challenge_manager_token_verification() {
    let manager = ChallengeManager::default();
    let token = manager.generate_token();

    assert!(manager.verify_token(&token), "Fresh token should be valid");
}

#[test]
fn test_challenge_manager_invalid_tokens() {
    let manager = ChallengeManager::default();

    assert!(!manager.verify_token("invalid"));
    assert!(!manager.verify_token("a|b|c"));
    assert!(!manager.verify_token(""));
    assert!(!manager.verify_token("1|2"));
    assert!(!manager.verify_token("not|a|timestamp|extra"));
}

#[test]
fn test_challenge_manager_expired_token() {
    let manager = ChallengeManager::new(
        "secret",
        0, // 0 second validity
        "cookie",
        ChallengeType::JavaScript,
        None,
        None,
    );

    let token = manager.generate_token();
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(!manager.verify_token(&token), "Expired token should fail");
}

#[test]
fn test_challenge_manager_cookie_extraction() {
    let manager = ChallengeManager::new(
        "secret",
        300,
        "bot_check",
        ChallengeType::JavaScript,
        None,
        None,
    );

    // Token present
    let cookies = "session=abc123; bot_check=token_value; other=xyz";
    let token = manager.extract_token_from_cookies(cookies);
    assert_eq!(token, Some("token_value".to_string()));

    // Token not present
    let no_cookie = "session=abc123; other=xyz";
    let token = manager.extract_token_from_cookies(no_cookie);
    assert_eq!(token, None);

    // Empty string
    assert_eq!(manager.extract_token_from_cookies(""), None);
}

#[test]
fn test_challenge_manager_challenge_params_javascript() {
    let manager = ChallengeManager::new(
        "secret",
        300,
        "cookie",
        ChallengeType::JavaScript,
        Some("/challenge.js".to_string()),
        None,
    );

    let params = manager.get_challenge_params(&ChallengeType::JavaScript);

    assert!(params.contains_key("challenge_url"));
    assert!(params.contains_key("token"));
    assert!(params.contains_key("cookie_name"));
    assert_eq!(params.get("challenge_url"), Some(&"/challenge.js".to_string()));
}

#[test]
fn test_challenge_manager_challenge_params_captcha() {
    let manager = ChallengeManager::new(
        "secret",
        300,
        "cookie",
        ChallengeType::Captcha,
        None,
        Some("/captcha".to_string()),
    );

    let params = manager.get_challenge_params(&ChallengeType::Captcha);

    assert!(params.contains_key("token"));
    assert!(params.contains_key("challenge_url"));
}

#[test]
fn test_challenge_manager_challenge_params_pow() {
    let manager = ChallengeManager::default();
    let params = manager.get_challenge_params(&ChallengeType::ProofOfWork);

    assert!(params.contains_key("token"));
    assert!(params.contains_key("difficulty"));
    assert_eq!(params.get("difficulty"), Some(&"4".to_string()));
}

#[test]
fn test_challenge_manager_different_secrets() {
    let manager1 = ChallengeManager::new(
        "secret1",
        300,
        "cookie",
        ChallengeType::JavaScript,
        None,
        None,
    );
    let manager2 = ChallengeManager::new(
        "secret2",
        300,
        "cookie",
        ChallengeType::JavaScript,
        None,
        None,
    );

    let token1 = manager1.generate_token();

    // Token from manager1 should not verify with manager2
    assert!(!manager2.verify_token(&token1));
}

// =============================================================================
// Detection Context Tests
// =============================================================================

fn make_detection_context(ua: &str, client_ip: &str) -> DetectionContext {
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), vec![ua.to_string()]);
    headers.insert("accept".to_string(), vec!["text/html".to_string()]);

    DetectionContext {
        headers,
        client_ip: client_ip.parse().unwrap(),
        path: "/".to_string(),
        method: "GET".to_string(),
        correlation_id: "test-123".to_string(),
    }
}

#[test]
fn test_detection_context_header_access() {
    let ctx = make_detection_context("Mozilla/5.0", "192.168.1.1");

    assert_eq!(ctx.header("user-agent"), Some("Mozilla/5.0"));
    assert_eq!(ctx.header("User-Agent"), Some("Mozilla/5.0")); // case insensitive
    assert_eq!(ctx.header("accept"), Some("text/html"));
    assert_eq!(ctx.header("nonexistent"), None);
}

#[test]
fn test_detection_context_user_agent() {
    let ctx = make_detection_context("TestBot/1.0", "10.0.0.1");
    assert_eq!(ctx.user_agent(), Some("TestBot/1.0"));

    let headers = HashMap::new();
    let ctx_no_ua = DetectionContext {
        headers,
        client_ip: "127.0.0.1".parse().unwrap(),
        path: "/".to_string(),
        method: "GET".to_string(),
        correlation_id: "test".to_string(),
    };
    assert_eq!(ctx_no_ua.user_agent(), None);
}

// =============================================================================
// Detector Result Tests
// =============================================================================

#[test]
fn test_detector_result_new() {
    let result = DetectorResult::new(75);

    assert_eq!(result.score, 75);
    assert!(result.reasons.is_empty());
    assert!(result.metadata.is_empty());
}

#[test]
fn test_detector_result_with_reason() {
    let result = DetectorResult::new(50)
        .with_reason("bot_keyword_detected")
        .with_reason("suspicious_headers");

    assert_eq!(result.reasons.len(), 2);
    assert!(result.reasons.contains(&"bot_keyword_detected".to_string()));
    assert!(result.reasons.contains(&"suspicious_headers".to_string()));
}

#[test]
fn test_detector_result_with_metadata() {
    let result = DetectorResult::new(40)
        .with_metadata("user_agent", "curl/7.88")
        .with_metadata("detected_bot", "true");

    assert_eq!(result.metadata.get("user_agent"), Some(&"curl/7.88".to_string()));
    assert_eq!(result.metadata.get("detected_bot"), Some(&"true".to_string()));
}

// =============================================================================
// User Agent Analyzer Tests
// =============================================================================

#[tokio::test]
async fn test_ua_analyzer_normal_browser() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "192.168.1.1",
    );
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score < 30, "Normal browser should have low score: {}", result.score);
}

#[tokio::test]
async fn test_ua_analyzer_curl() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context("curl/7.88.0", "192.168.1.1");
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 50, "curl should have moderate score");
    assert!(result.reasons.iter().any(|r| r.contains("curl")));
}

#[tokio::test]
async fn test_ua_analyzer_python_requests() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context("python-requests/2.28.0", "192.168.1.1");
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 40, "Python requests should have moderate score");
}

#[tokio::test]
async fn test_ua_analyzer_security_scanner() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context("sqlmap/1.0", "192.168.1.1");
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 80, "Security scanner should have high score");
}

#[tokio::test]
async fn test_ua_analyzer_headless_browser() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0",
        "192.168.1.1",
    );
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 50, "Headless browser should have moderate-high score");
    assert!(result.reasons.iter().any(|r| r.contains("headless")));
}

#[tokio::test]
async fn test_ua_analyzer_missing_ua() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = DetectionContext {
        headers: HashMap::new(),
        client_ip: "127.0.0.1".parse().unwrap(),
        path: "/".to_string(),
        method: "GET".to_string(),
        correlation_id: "test".to_string(),
    };
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 70, "Missing UA should have high score");
    assert!(result.reasons.iter().any(|r| r.contains("missing")));
}

#[tokio::test]
async fn test_ua_analyzer_empty_ua() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context("", "192.168.1.1");
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 70, "Empty UA should have high score");
}

#[tokio::test]
async fn test_ua_analyzer_short_ua() {
    let analyzer = UserAgentAnalyzer::new();
    let ctx = make_detection_context("Bot", "192.168.1.1");
    let result = analyzer.analyze(&ctx).await;

    assert!(result.reasons.iter().any(|r| r.contains("short")));
}

// =============================================================================
// Header Analyzer Tests
// =============================================================================

fn make_context_with_headers(headers: Vec<(&str, &str)>) -> DetectionContext {
    let mut header_map = HashMap::new();
    for (k, v) in headers {
        header_map.insert(k.to_lowercase(), vec![v.to_string()]);
    }

    DetectionContext {
        headers: header_map,
        client_ip: "192.168.1.1".parse().unwrap(),
        path: "/".to_string(),
        method: "GET".to_string(),
        correlation_id: "test".to_string(),
    }
}

#[tokio::test]
async fn test_header_analyzer_normal_browser() {
    let analyzer = HeaderAnalyzer::new();
    let ctx = make_context_with_headers(vec![
        ("user-agent", "Mozilla/5.0"),
        ("accept", "text/html,application/xhtml+xml"),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br"),
        ("connection", "keep-alive"),
    ]);
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score < 40, "Normal browser headers should have low score: {}", result.score);
}

#[tokio::test]
async fn test_header_analyzer_minimal_headers() {
    let analyzer = HeaderAnalyzer::new();
    let ctx = make_context_with_headers(vec![
        ("user-agent", "Bot/1.0"),
    ]);
    let result = analyzer.analyze(&ctx).await;

    assert!(result.score >= 30, "Minimal headers should have moderate score");
}

// =============================================================================
// Agent Creation Tests
// =============================================================================

#[tokio::test]
async fn test_agent_creation_with_default_config() {
    let config = BotManagementConfig::default();
    let good_bots_path = std::path::Path::new("data/good_bots.json");
    let bad_patterns_path = std::path::Path::new("data/bad_patterns.json");
    let _agent = BotManagementAgent::new(config, good_bots_path, bad_patterns_path)
        .await
        .expect("Failed to create agent");
}

#[tokio::test]
async fn test_agent_creation_with_custom_config() {
    let config = BotManagementConfig {
        thresholds: ThresholdConfig {
            allow_threshold: 20,
            block_threshold: 90,
            min_confidence: 0.6,
        },
        detection: DetectionConfig {
            header_analysis: true,
            user_agent_validation: true,
            known_bot_lookup: false,
            behavioral_analysis: false,
            weights: SignalWeights::default(),
        },
        allow_list: AllowListConfig::default(),
        challenge: ChallengeConfig::default(),
        behavioral: BehavioralConfig::default(),
        cache: CacheConfig::default(),
        performance: PerformanceConfig::default(),
        debug_headers: true,
    };

    let good_bots_path = std::path::Path::new("data/good_bots.json");
    let bad_patterns_path = std::path::Path::new("data/bad_patterns.json");
    let _agent = BotManagementAgent::new(config, good_bots_path, bad_patterns_path)
        .await
        .expect("Failed to create agent");
}

// =============================================================================
// Signal Breakdown Tests
// =============================================================================

#[test]
fn test_signal_breakdown_default() {
    let signals = SignalBreakdown::default();

    assert!(signals.header_score.is_none());
    assert!(signals.user_agent_score.is_none());
    assert!(signals.known_bot_score.is_none());
    assert!(signals.behavioral_score.is_none());
    assert!(signals.reasons.is_empty());
}

#[test]
fn test_signal_breakdown_serialization() {
    let signals = SignalBreakdown {
        header_score: Some(30),
        user_agent_score: Some(50),
        known_bot_score: Some(0),
        behavioral_score: None,
        reasons: vec!["test_reason".to_string()],
    };

    let json = serde_json::to_string(&signals).unwrap();
    assert!(json.contains("header_score"));
    assert!(json.contains("30"));

    let parsed: SignalBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.header_score, Some(30));
    assert_eq!(parsed.user_agent_score, Some(50));
}

// =============================================================================
// Challenge Type Tests
// =============================================================================

#[test]
fn test_challenge_type_serialization() {
    let js = ChallengeType::JavaScript;
    let captcha = ChallengeType::Captcha;
    let pow = ChallengeType::ProofOfWork;

    let js_json = serde_json::to_string(&js).unwrap();
    let captcha_json = serde_json::to_string(&captcha).unwrap();
    let pow_json = serde_json::to_string(&pow).unwrap();

    assert_eq!(js_json, "\"java_script\"");
    assert_eq!(captcha_json, "\"captcha\"");
    assert_eq!(pow_json, "\"proof_of_work\"");
}

#[test]
fn test_challenge_type_deserialization() {
    let js: ChallengeType = serde_json::from_str("\"java_script\"").unwrap();
    let captcha: ChallengeType = serde_json::from_str("\"captcha\"").unwrap();

    assert_eq!(js, ChallengeType::JavaScript);
    assert_eq!(captcha, ChallengeType::Captcha);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_empty_config_uses_defaults() {
    let json = "{}";
    let config: BotManagementConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.thresholds.allow_threshold, 30);
    assert_eq!(config.thresholds.block_threshold, 80);
}

#[test]
fn test_score_bounds() {
    // Score should always be 0-100
    let calc = ScoreCalculator::default();

    let high_signals = SignalBreakdown {
        header_score: Some(100),
        user_agent_score: Some(100),
        known_bot_score: Some(100),
        behavioral_score: Some(100),
        reasons: vec![],
    };
    let score = calc.calculate(&high_signals);
    assert!(score.score <= 100);

    let low_signals = SignalBreakdown {
        header_score: Some(0),
        user_agent_score: Some(0),
        known_bot_score: Some(0),
        behavioral_score: Some(0),
        reasons: vec![],
    };
    let score = calc.calculate(&low_signals);
    assert_eq!(score.score, 0, "All zero signals should produce zero score");
}
