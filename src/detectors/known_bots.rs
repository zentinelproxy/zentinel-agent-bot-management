//! Known bot database detector.
//!
//! Identifies known good and bad bots based on:
//! - User-Agent patterns
//! - IP ranges
//! - Reverse DNS verification

use super::{DetectionContext, Detector, DetectorResult};
use crate::score::BotCategory;
use async_trait::async_trait;
use ipnet::IpNet;
use moka::future::Cache;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// A known bot definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownBot {
    /// Bot name (e.g., "Googlebot")
    pub name: String,

    /// Bot category
    pub category: String,

    /// User-Agent patterns to match
    pub ua_patterns: Vec<String>,

    /// IP ranges (CIDR notation)
    #[serde(default)]
    pub ip_ranges: Vec<String>,

    /// Reverse DNS suffix for verification
    #[serde(default)]
    pub verify_dns: Option<String>,

    /// Whether this is a "good" bot
    #[serde(default = "default_true")]
    pub is_good: bool,
}

fn default_true() -> bool {
    true
}

/// Known bot database.
pub struct KnownBotDatabase {
    /// Good bots
    good_bots: Vec<CompiledBot>,
    /// Bad bot patterns
    bad_patterns: Vec<CompiledPattern>,
    /// IP to bot verification cache
    verification_cache: Cache<(IpAddr, String), VerificationResult>,
    /// DNS resolver
    resolver: TokioAsyncResolver,
    /// Whether to verify bot identity
    verify_identity: bool,
}

/// Compiled bot definition with pre-compiled regexes.
struct CompiledBot {
    name: String,
    category: BotCategory,
    ua_patterns: Vec<Regex>,
    ip_ranges: Vec<IpNet>,
    verify_dns: Option<String>,
    #[allow(dead_code)] // Reserved for future use with mixed good/bad bot lists
    is_good: bool,
}

/// Compiled bad pattern.
struct CompiledPattern {
    pattern: Regex,
    reason: String,
    score: u8,
}

/// Result of bot verification.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Verified as a legitimate bot
    Verified(String, BotCategory),
    /// Failed verification (fake bot)
    Fake(String),
    /// Unknown / not in database
    Unknown,
}

impl KnownBotDatabase {
    /// Create a new known bot database.
    pub async fn new(
        good_bots_path: &Path,
        bad_patterns_path: &Path,
        verify_identity: bool,
        cache_size: u64,
        cache_ttl: Duration,
    ) -> anyhow::Result<Self> {
        // Load good bots
        let good_bots = if good_bots_path.exists() {
            let content = std::fs::read_to_string(good_bots_path)?;
            let bots: Vec<KnownBot> = serde_json::from_str(&content)?;
            bots.into_iter()
                .filter_map(|b| Self::compile_bot(b).ok())
                .collect()
        } else {
            Self::default_good_bots()
        };

        // Load bad patterns
        let bad_patterns = if bad_patterns_path.exists() {
            let content = std::fs::read_to_string(bad_patterns_path)?;
            let patterns: Vec<BadPatternDef> = serde_json::from_str(&content)?;
            patterns.into_iter()
                .filter_map(|p| Self::compile_bad_pattern(p).ok())
                .collect()
        } else {
            Self::default_bad_patterns()
        };

        // Create DNS resolver
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Create cache
        let verification_cache = Cache::builder()
            .max_capacity(cache_size)
            .time_to_live(cache_ttl)
            .build();

        Ok(Self {
            good_bots,
            bad_patterns,
            verification_cache,
            resolver,
            verify_identity,
        })
    }

    /// Create with default databases.
    pub async fn with_defaults(verify_identity: bool) -> anyhow::Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let verification_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(3600))
            .build();

        Ok(Self {
            good_bots: Self::default_good_bots(),
            bad_patterns: Self::default_bad_patterns(),
            verification_cache,
            resolver,
            verify_identity,
        })
    }

    fn compile_bot(bot: KnownBot) -> anyhow::Result<CompiledBot> {
        let ua_patterns: Vec<Regex> = bot.ua_patterns
            .iter()
            .filter_map(|p| Regex::new(&format!("(?i){}", regex::escape(p))).ok())
            .collect();

        let ip_ranges: Vec<IpNet> = bot.ip_ranges
            .iter()
            .filter_map(|r| r.parse().ok())
            .collect();

        let category = match bot.category.to_lowercase().as_str() {
            "search_engine" => BotCategory::SearchEngine,
            "social_media" => BotCategory::SocialMedia,
            "monitoring" => BotCategory::Monitoring,
            "seo_tool" => BotCategory::SeoTool,
            "security_scanner" => BotCategory::SecurityScanner,
            _ => BotCategory::Unknown,
        };

        Ok(CompiledBot {
            name: bot.name,
            category,
            ua_patterns,
            ip_ranges,
            verify_dns: bot.verify_dns,
            is_good: bot.is_good,
        })
    }

    fn compile_bad_pattern(pattern: BadPatternDef) -> anyhow::Result<CompiledPattern> {
        Ok(CompiledPattern {
            pattern: Regex::new(&pattern.pattern)?,
            reason: pattern.reason,
            score: pattern.score,
        })
    }

    fn default_good_bots() -> Vec<CompiledBot> {
        vec![
            CompiledBot {
                name: "Googlebot".to_string(),
                category: BotCategory::SearchEngine,
                ua_patterns: vec![
                    Regex::new(r"(?i)googlebot").expect("valid regex: googlebot"),
                    Regex::new(r"(?i)google-inspectiontool").expect("valid regex: google-inspectiontool"),
                    Regex::new(r"(?i)googleother").expect("valid regex: googleother"),
                ],
                ip_ranges: vec![
                    "66.249.64.0/19".parse().expect("valid CIDR: 66.249.64.0/19"),
                    "64.233.160.0/19".parse().expect("valid CIDR: 64.233.160.0/19"),
                    "66.102.0.0/20".parse().expect("valid CIDR: 66.102.0.0/20"),
                    "72.14.192.0/18".parse().expect("valid CIDR: 72.14.192.0/18"),
                    "74.125.0.0/16".parse().expect("valid CIDR: 74.125.0.0/16"),
                    "209.85.128.0/17".parse().expect("valid CIDR: 209.85.128.0/17"),
                    "216.239.32.0/19".parse().expect("valid CIDR: 216.239.32.0/19"),
                ],
                verify_dns: Some(".googlebot.com".to_string()),
                is_good: true,
            },
            CompiledBot {
                name: "Bingbot".to_string(),
                category: BotCategory::SearchEngine,
                ua_patterns: vec![
                    Regex::new(r"(?i)bingbot").expect("valid regex: bingbot"),
                    Regex::new(r"(?i)msnbot").expect("valid regex: msnbot"),
                ],
                ip_ranges: vec![
                    "40.77.167.0/24".parse().expect("valid CIDR: 40.77.167.0/24"),
                    "207.46.0.0/16".parse().expect("valid CIDR: 207.46.0.0/16"),
                    "65.52.0.0/14".parse().expect("valid CIDR: 65.52.0.0/14"),
                    "157.55.0.0/16".parse().expect("valid CIDR: 157.55.0.0/16"),
                    "157.56.0.0/16".parse().expect("valid CIDR: 157.56.0.0/16"),
                ],
                verify_dns: Some(".search.msn.com".to_string()),
                is_good: true,
            },
            CompiledBot {
                name: "DuckDuckBot".to_string(),
                category: BotCategory::SearchEngine,
                ua_patterns: vec![
                    Regex::new(r"(?i)duckduckbot").expect("valid regex: duckduckbot"),
                ],
                ip_ranges: vec![
                    "20.191.45.212/32".parse().expect("valid CIDR: 20.191.45.212/32"),
                    "40.88.21.235/32".parse().expect("valid CIDR: 40.88.21.235/32"),
                    "40.76.173.151/32".parse().expect("valid CIDR: 40.76.173.151/32"),
                    "40.76.163.7/32".parse().expect("valid CIDR: 40.76.163.7/32"),
                    "20.185.79.47/32".parse().expect("valid CIDR: 20.185.79.47/32"),
                ],
                verify_dns: None, // DuckDuckBot doesn't have reverse DNS
                is_good: true,
            },
            CompiledBot {
                name: "Facebookbot".to_string(),
                category: BotCategory::SocialMedia,
                ua_patterns: vec![
                    Regex::new(r"(?i)facebookexternalhit").expect("valid regex: facebookexternalhit"),
                    Regex::new(r"(?i)facebot").expect("valid regex: facebot"),
                ],
                ip_ranges: vec![],
                verify_dns: None,
                is_good: true,
            },
            CompiledBot {
                name: "Twitterbot".to_string(),
                category: BotCategory::SocialMedia,
                ua_patterns: vec![
                    Regex::new(r"(?i)twitterbot").expect("valid regex: twitterbot"),
                ],
                ip_ranges: vec![],
                verify_dns: None,
                is_good: true,
            },
            CompiledBot {
                name: "UptimeRobot".to_string(),
                category: BotCategory::Monitoring,
                ua_patterns: vec![
                    Regex::new(r"(?i)uptimerobot").expect("valid regex: uptimerobot"),
                ],
                ip_ranges: vec![],
                verify_dns: None,
                is_good: true,
            },
            CompiledBot {
                name: "Pingdom".to_string(),
                category: BotCategory::Monitoring,
                ua_patterns: vec![
                    Regex::new(r"(?i)pingdom").expect("valid regex: pingdom"),
                ],
                ip_ranges: vec![],
                verify_dns: None,
                is_good: true,
            },
        ]
    }

    fn default_bad_patterns() -> Vec<CompiledPattern> {
        vec![
            CompiledPattern {
                pattern: Regex::new(r"(?i)sqlmap").expect("valid regex: sqlmap"),
                reason: "security_scanner_sqlmap".to_string(),
                score: 95,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)nikto").expect("valid regex: nikto"),
                reason: "security_scanner_nikto".to_string(),
                score: 95,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)nessus").expect("valid regex: nessus"),
                reason: "security_scanner_nessus".to_string(),
                score: 90,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)masscan").expect("valid regex: masscan"),
                reason: "port_scanner_masscan".to_string(),
                score: 90,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)zgrab").expect("valid regex: zgrab"),
                reason: "security_scanner_zgrab".to_string(),
                score: 85,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)gobuster").expect("valid regex: gobuster"),
                reason: "directory_scanner_gobuster".to_string(),
                score: 85,
            },
            CompiledPattern {
                pattern: Regex::new(r"(?i)nuclei").expect("valid regex: nuclei"),
                reason: "vulnerability_scanner_nuclei".to_string(),
                score: 90,
            },
        ]
    }

    /// Check if a UA matches a known bot and verify if needed.
    pub async fn check(&self, ctx: &DetectionContext) -> VerificationResult {
        let ua = match ctx.user_agent() {
            Some(ua) => ua,
            None => return VerificationResult::Unknown,
        };

        // Check cache first
        let cache_key = (ctx.client_ip, ua.to_string());
        if let Some(cached) = self.verification_cache.get(&cache_key).await {
            return cached;
        }

        // Check against known good bots
        for bot in &self.good_bots {
            if bot.ua_patterns.iter().any(|p| p.is_match(ua)) {
                let result = if self.verify_identity {
                    self.verify_bot(bot, ctx.client_ip).await
                } else {
                    VerificationResult::Verified(bot.name.clone(), bot.category.clone())
                };

                // Cache the result
                self.verification_cache.insert(cache_key, result.clone()).await;
                return result;
            }
        }

        let result = VerificationResult::Unknown;
        self.verification_cache.insert(cache_key, result.clone()).await;
        result
    }

    /// Verify a bot's identity via IP range or reverse DNS.
    async fn verify_bot(&self, bot: &CompiledBot, ip: IpAddr) -> VerificationResult {
        // Check IP ranges first (faster)
        for range in &bot.ip_ranges {
            if range.contains(&ip) {
                return VerificationResult::Verified(bot.name.clone(), bot.category.clone());
            }
        }

        // Try reverse DNS verification
        if let Some(dns_suffix) = &bot.verify_dns {
            if let Ok(hostnames) = self.resolver.reverse_lookup(ip).await {
                for hostname in hostnames.iter() {
                    let host = hostname.to_string();
                    if host.ends_with(dns_suffix) || host.ends_with(&format!("{}.", dns_suffix)) {
                        // Forward verify: lookup the hostname and check if it resolves back to the IP
                        if let Ok(ips) = self.resolver.lookup_ip(&host).await {
                            if ips.iter().any(|resolved_ip| resolved_ip == ip) {
                                return VerificationResult::Verified(bot.name.clone(), bot.category.clone());
                            }
                        }
                    }
                }
            }
            // Claims to be this bot but doesn't verify
            return VerificationResult::Fake(format!("Fake {} - IP verification failed", bot.name));
        }

        // No verification method available, trust the UA
        VerificationResult::Verified(bot.name.clone(), bot.category.clone())
    }

    /// Check against bad patterns.
    pub fn check_bad_patterns(&self, ua: &str) -> Option<(String, u8)> {
        for pattern in &self.bad_patterns {
            if pattern.pattern.is_match(ua) {
                return Some((pattern.reason.clone(), pattern.score));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BadPatternDef {
    pattern: String,
    reason: String,
    score: u8,
}

#[async_trait]
impl Detector for KnownBotDatabase {
    async fn analyze(&self, ctx: &DetectionContext) -> DetectorResult {
        let ua = match ctx.user_agent() {
            Some(ua) => ua,
            None => return DetectorResult::new(50), // Unknown without UA
        };

        // Check bad patterns first
        if let Some((reason, score)) = self.check_bad_patterns(ua) {
            return DetectorResult::new(score)
                .with_reason(reason)
                .with_metadata("matched_type", "bad_pattern".to_string());
        }

        // Check known bots
        match self.check(ctx).await {
            VerificationResult::Verified(name, _category) => {
                DetectorResult::new(0)
                    .with_reason(format!("verified_bot_{}", name.to_lowercase().replace(' ', "_")))
                    .with_metadata("verified_bot", name)
                    .with_metadata("matched_type", "verified_good".to_string())
            }
            VerificationResult::Fake(reason) => {
                DetectorResult::new(100)
                    .with_reason(reason)
                    .with_metadata("matched_type", "fake_bot".to_string())
            }
            VerificationResult::Unknown => {
                DetectorResult::new(50) // Neutral - not in our database
                    .with_metadata("matched_type", "unknown".to_string())
            }
        }
    }

    fn name(&self) -> &'static str {
        "known_bot_database"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_ctx(ua: &str, ip: &str) -> DetectionContext {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), vec![ua.to_string()]);
        DetectionContext {
            headers,
            client_ip: ip.parse().unwrap(),
            path: "/".to_string(),
            method: "GET".to_string(),
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_known_bot_detection() {
        let db = KnownBotDatabase::with_defaults(false).await.unwrap();

        // Googlebot without verification
        let ctx = make_ctx("Googlebot/2.1", "127.0.0.1");
        let result = db.analyze(&ctx).await;
        assert_eq!(result.score, 0, "Googlebot should have score 0");
    }

    #[tokio::test]
    async fn test_bad_pattern_detection() {
        let db = KnownBotDatabase::with_defaults(false).await.unwrap();

        let ctx = make_ctx("sqlmap/1.0", "127.0.0.1");
        let result = db.analyze(&ctx).await;
        assert!(result.score >= 90, "sqlmap should have high score");
    }

    #[tokio::test]
    async fn test_unknown_ua() {
        let db = KnownBotDatabase::with_defaults(false).await.unwrap();

        let ctx = make_ctx("MyCustomBot/1.0", "127.0.0.1");
        let result = db.analyze(&ctx).await;
        assert_eq!(result.score, 50, "Unknown bot should have neutral score");
    }
}
