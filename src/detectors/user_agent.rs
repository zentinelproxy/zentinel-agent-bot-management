//! User-Agent analysis detector.
//!
//! Analyzes the User-Agent string for bot indicators:
//! - Known bot keywords
//! - Automation tool signatures
//! - Suspicious patterns
//! - Version validation

use super::{DetectionContext, Detector, DetectorResult};
use async_trait::async_trait;
use regex::Regex;
use std::sync::LazyLock;

/// Known bot keywords in User-Agent strings.
static BOT_KEYWORDS: LazyLock<Vec<(&'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Generic bot indicators (moderate score)
        ("bot", 40),
        ("crawler", 40),
        ("spider", 40),
        ("scraper", 50),

        // Command-line tools (moderate score)
        ("curl", 50),
        ("wget", 50),
        ("httpie", 50),
        ("postman", 30),

        // Programming libraries (moderate score)
        ("python-requests", 45),
        ("python-urllib", 45),
        ("go-http-client", 45),
        ("java/", 40),
        ("axios", 35),
        ("node-fetch", 40),
        ("okhttp", 35),

        // Security scanners (high score)
        ("sqlmap", 90),
        ("nikto", 90),
        ("nessus", 90),
        ("nmap", 90),
        ("masscan", 90),
        ("zgrab", 85),
        ("gobuster", 85),
        ("dirbuster", 85),
        ("nuclei", 85),

        // Headless browsers (moderate-high score)
        ("headless", 60),
        ("phantomjs", 70),
        ("puppeteer", 60),
        ("playwright", 60),
        ("selenium", 60),

        // Known bad bots
        ("ahrefsbot", 45),
        ("semrushbot", 45),
        ("mj12bot", 50),
        ("dotbot", 45),
        ("blexbot", 50),
    ]
});

/// Patterns for outdated browsers (suspicious).
static OUTDATED_PATTERNS: LazyLock<Vec<(Regex, &'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Very old Chrome versions (Chrome 90+ is current as of 2024)
        (Regex::new(r"Chrome/([1-7][0-9])\.").unwrap(), "outdated_chrome", 30),
        // Very old Firefox versions
        (Regex::new(r"Firefox/([1-7][0-9])\.").unwrap(), "outdated_firefox", 30),
        // IE is always suspicious in 2024+
        (Regex::new(r"MSIE|Trident").unwrap(), "internet_explorer", 40),
    ]
});

/// Patterns for impossible/inconsistent User-Agents.
static IMPOSSIBLE_PATTERNS: LazyLock<Vec<(Regex, &'static str, u8)>> = LazyLock::new(|| {
    vec![
        // Android + Windows
        (Regex::new(r"(?i)android.*windows|windows.*android").unwrap(), "android_windows", 70),
        // iPhone + Android
        (Regex::new(r"(?i)iphone.*android|android.*iphone").unwrap(), "iphone_android", 70),
        // Mac + Windows
        (Regex::new(r"(?i)macintosh.*windows nt|windows nt.*macintosh").unwrap(), "mac_windows", 70),
        // Too many browser engines
        (Regex::new(r"Chrome.*Firefox.*Safari.*Edge").unwrap(), "too_many_engines", 60),
    ]
});

/// User-Agent analyzer detector.
pub struct UserAgentAnalyzer {
    /// Minimum Chrome version to consider current
    min_chrome_version: u32,
    /// Minimum Firefox version to consider current
    min_firefox_version: u32,
}

impl UserAgentAnalyzer {
    /// Create a new User-Agent analyzer.
    pub fn new() -> Self {
        Self {
            min_chrome_version: 90,
            min_firefox_version: 90,
        }
    }

    /// Check for bot keywords in the User-Agent.
    fn check_keywords(&self, ua: &str) -> (u8, Vec<String>) {
        let ua_lower = ua.to_lowercase();
        let mut max_score = 0u8;
        let mut reasons = Vec::new();

        for (keyword, score) in BOT_KEYWORDS.iter() {
            if ua_lower.contains(keyword) {
                if *score > max_score {
                    max_score = *score;
                }
                reasons.push(format!("bot_keyword_{}", keyword.replace('-', "_").replace('/', "_")));
            }
        }

        (max_score, reasons)
    }

    /// Check for outdated browser versions.
    fn check_outdated(&self, ua: &str) -> (u8, Vec<String>) {
        let mut score = 0u8;
        let mut reasons = Vec::new();

        for (pattern, reason, pattern_score) in OUTDATED_PATTERNS.iter() {
            if pattern.is_match(ua) {
                score = score.max(*pattern_score);
                reasons.push(reason.to_string());
            }
        }

        score = score.saturating_add(self.check_browser_version(ua));

        (score, reasons)
    }

    /// Check browser version against minimums.
    fn check_browser_version(&self, ua: &str) -> u8 {
        // Extract Chrome version
        if let Some(version) = Self::extract_version(ua, "Chrome/") {
            if version < self.min_chrome_version && version > 0 {
                return 25;
            }
        }

        // Extract Firefox version
        if let Some(version) = Self::extract_version(ua, "Firefox/") {
            if version < self.min_firefox_version && version > 0 {
                return 25;
            }
        }

        0
    }

    /// Extract version number from User-Agent.
    fn extract_version(ua: &str, prefix: &str) -> Option<u32> {
        let idx = ua.find(prefix)?;
        let start = idx + prefix.len();
        let rest = &ua[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    /// Check for impossible/inconsistent User-Agents.
    fn check_impossible(&self, ua: &str) -> (u8, Vec<String>) {
        let mut score = 0u8;
        let mut reasons = Vec::new();

        for (pattern, reason, pattern_score) in IMPOSSIBLE_PATTERNS.iter() {
            if pattern.is_match(ua) {
                score = score.max(*pattern_score);
                reasons.push(reason.to_string());
            }
        }

        (score, reasons)
    }
}

impl Default for UserAgentAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for UserAgentAnalyzer {
    async fn analyze(&self, ctx: &DetectionContext) -> DetectorResult {
        let ua = match ctx.user_agent() {
            Some(ua) => ua,
            None => {
                // No User-Agent is very suspicious
                return DetectorResult::new(80)
                    .with_reason("missing_user_agent".to_string());
            }
        };

        // Empty User-Agent is suspicious
        if ua.trim().is_empty() {
            return DetectorResult::new(75)
                .with_reason("empty_user_agent".to_string());
        }

        let mut total_score = 0u8;
        let mut all_reasons = Vec::new();

        // Check for bot keywords
        let (keyword_score, keyword_reasons) = self.check_keywords(ua);
        total_score = total_score.saturating_add(keyword_score);
        all_reasons.extend(keyword_reasons);

        // Check for outdated versions
        let (outdated_score, outdated_reasons) = self.check_outdated(ua);
        total_score = total_score.saturating_add(outdated_score);
        all_reasons.extend(outdated_reasons);

        // Check for impossible combinations
        let (impossible_score, impossible_reasons) = self.check_impossible(ua);
        total_score = total_score.saturating_add(impossible_score);
        all_reasons.extend(impossible_reasons);

        // Very short User-Agents are suspicious
        if ua.len() < 20 {
            total_score = total_score.saturating_add(20);
            all_reasons.push("short_user_agent".to_string());
        }

        let mut result = DetectorResult::new(total_score.min(100));
        for reason in all_reasons {
            result = result.with_reason(reason);
        }
        result = result.with_metadata("user_agent", ua.to_string());

        result
    }

    fn name(&self) -> &'static str {
        "user_agent_analyzer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_ctx(ua: &str) -> DetectionContext {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), vec![ua.to_string()]);
        DetectionContext {
            headers,
            client_ip: "127.0.0.1".parse().unwrap(),
            path: "/".to_string(),
            method: "GET".to_string(),
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_normal_browser() {
        let analyzer = UserAgentAnalyzer::new();
        let ctx = make_ctx("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score < 30, "Normal browser should have low score: {}", result.score);
    }

    #[tokio::test]
    async fn test_curl() {
        let analyzer = UserAgentAnalyzer::new();
        let ctx = make_ctx("curl/7.88.0");
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score >= 50, "curl should have moderate score");
        assert!(result.reasons.iter().any(|r| r.contains("curl")));
    }

    #[tokio::test]
    async fn test_security_scanner() {
        let analyzer = UserAgentAnalyzer::new();
        let ctx = make_ctx("sqlmap/1.0");
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score >= 80, "Security scanner should have high score");
    }

    #[tokio::test]
    async fn test_missing_ua() {
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
    }

    #[tokio::test]
    async fn test_impossible_ua() {
        let analyzer = UserAgentAnalyzer::new();
        let ctx = make_ctx("Mozilla/5.0 (Windows NT; Android 10) Chrome/120");
        let result = analyzer.analyze(&ctx).await;
        assert!(result.score >= 50, "Impossible UA should have moderate-high score");
    }

    #[tokio::test]
    async fn test_version_extraction() {
        assert_eq!(UserAgentAnalyzer::extract_version("Chrome/120.0.0.0", "Chrome/"), Some(120));
        assert_eq!(UserAgentAnalyzer::extract_version("Firefox/115.0", "Firefox/"), Some(115));
        assert_eq!(UserAgentAnalyzer::extract_version("Safari/537.36", "Chrome/"), None);
    }
}
