//! Header analysis detector.
//!
//! Analyzes request headers for bot indicators:
//! - Missing common browser headers
//! - Automation tool markers
//! - Header inconsistencies

use super::{DetectionContext, Detector, DetectorResult};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Headers that real browsers typically send.
static BROWSER_HEADERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "accept",
        "accept-language",
        "accept-encoding",
    ])
});

/// Headers that indicate automation tools.
static AUTOMATION_HEADERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "x-selenium",
        "x-puppeteer",
        "x-playwright",
        "x-automation",
        "x-headless",
        "x-requested-with",  // Sometimes set by automation
    ])
});

/// Suspicious header patterns.
static SUSPICIOUS_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (Regex::new(r"(?i)^selenium").unwrap(), "selenium_marker"),
        (Regex::new(r"(?i)^puppeteer").unwrap(), "puppeteer_marker"),
        (Regex::new(r"(?i)^playwright").unwrap(), "playwright_marker"),
        (Regex::new(r"(?i)headless").unwrap(), "headless_marker"),
    ]
});

/// Header analyzer detector.
pub struct HeaderAnalyzer {
    /// Required headers for browser detection
    required_headers: HashSet<&'static str>,
    /// Headers that indicate automation
    automation_headers: HashSet<&'static str>,
}

impl HeaderAnalyzer {
    /// Create a new header analyzer.
    pub fn new() -> Self {
        Self {
            required_headers: BROWSER_HEADERS.clone(),
            automation_headers: AUTOMATION_HEADERS.clone(),
        }
    }
}

impl Default for HeaderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for HeaderAnalyzer {
    async fn analyze(&self, ctx: &DetectionContext) -> DetectorResult {
        let mut score = 0u8;
        let mut result = DetectorResult::new(0);

        // Check for missing browser headers
        let mut missing_count = 0;
        for header in &self.required_headers {
            if !ctx.headers.contains_key(*header) {
                missing_count += 1;
                result = result.with_reason(format!("missing_{}", header.replace('-', "_")));
            }
        }

        // Score based on missing headers
        // Each missing header adds to suspicion
        score += (missing_count * 15).min(45) as u8;

        // Check for automation headers
        for header in &self.automation_headers {
            if ctx.headers.contains_key(*header) {
                score = score.saturating_add(30);
                result = result.with_reason(format!("automation_header_{}", header.replace('-', "_")));
            }
        }

        // Check header values for suspicious patterns
        for (_, values) in &ctx.headers {
            for value in values {
                for (pattern, reason) in SUSPICIOUS_PATTERNS.iter() {
                    if pattern.is_match(value) {
                        score = score.saturating_add(25);
                        result = result.with_reason(reason.to_string());
                    }
                }
            }
        }

        // Check for empty Accept header (bots often send empty or *)
        if let Some(accept) = ctx.header("accept") {
            if accept.is_empty() || accept == "*/*" {
                // Only flag if this is the only accept type (browsers send more specific)
                if !accept.contains("text/html") && !accept.contains("application/xhtml") {
                    score = score.saturating_add(10);
                    result = result.with_reason("generic_accept_header".to_string());
                }
            }
        }

        // Check for suspicious Accept-Language (missing or too simple)
        if let Some(accept_lang) = ctx.header("accept-language") {
            if accept_lang.len() < 2 {
                score = score.saturating_add(10);
                result = result.with_reason("suspicious_accept_language".to_string());
            }
        }

        // Check for sec-ch-ua headers (modern Chrome sends these)
        let has_sec_ch_ua = ctx.headers.contains_key("sec-ch-ua");
        let ua = ctx.header("user-agent").unwrap_or("");
        let claims_chrome = ua.contains("Chrome/") && !ua.contains("Chromium/");

        // Chrome 89+ should have sec-ch-ua
        if claims_chrome && !has_sec_ch_ua {
            // Extract Chrome version
            if let Some(version) = extract_chrome_version(ua) {
                if version >= 89 {
                    score = score.saturating_add(20);
                    result = result.with_reason("missing_sec_ch_ua_for_chrome".to_string());
                }
            }
        }

        result.score = score.min(100);
        result
    }

    fn name(&self) -> &'static str {
        "header_analyzer"
    }
}

/// Extract Chrome version from User-Agent string.
fn extract_chrome_version(ua: &str) -> Option<u32> {
    let chrome_idx = ua.find("Chrome/")?;
    let version_start = chrome_idx + 7;
    let rest = &ua[version_start..];
    let version_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..version_end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_ctx(headers: Vec<(&str, &str)>) -> DetectionContext {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.entry(k.to_lowercase())
                .or_insert_with(Vec::new)
                .push(v.to_string());
        }
        DetectionContext {
            headers: h,
            client_ip: "127.0.0.1".parse().unwrap(),
            path: "/".to_string(),
            method: "GET".to_string(),
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_browser_headers() {
        let analyzer = HeaderAnalyzer::new();

        // Full browser headers including sec-ch-ua for modern Chrome - low score
        let ctx = make_ctx(vec![
            ("accept", "text/html,application/xhtml+xml"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br"),
            ("user-agent", "Mozilla/5.0 Chrome/120"),
            ("sec-ch-ua", "\"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""),
        ]);
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score < 20, "Browser headers should have low score");

        // Missing headers - higher score
        let ctx = make_ctx(vec![
            ("user-agent", "curl/7.88.0"),
        ]);
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score >= 30, "Missing headers should increase score");
    }

    #[tokio::test]
    async fn test_automation_headers() {
        let analyzer = HeaderAnalyzer::new();

        let ctx = make_ctx(vec![
            ("x-selenium", "true"),
            ("accept", "text/html"),
            ("accept-language", "en"),
            ("accept-encoding", "gzip"),
        ]);
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score >= 30, "Automation headers should increase score");
        assert!(result.reasons.iter().any(|r| r.contains("automation")));
    }

    #[tokio::test]
    async fn test_chrome_version_extraction() {
        assert_eq!(extract_chrome_version("Mozilla/5.0 Chrome/120.0.0.0"), Some(120));
        assert_eq!(extract_chrome_version("Mozilla/5.0 Chrome/89"), Some(89));
        assert_eq!(extract_chrome_version("Mozilla/5.0 Firefox/120"), None);
    }
}
