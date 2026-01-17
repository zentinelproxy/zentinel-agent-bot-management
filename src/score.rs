//! Bot score calculation and types.

use serde::{Deserialize, Serialize};

/// Bot category classification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotCategory {
    /// Likely a human user
    Human,
    /// Search engine crawler (Google, Bing, etc.)
    SearchEngine,
    /// Social media crawler (Facebook, Twitter, etc.)
    SocialMedia,
    /// Monitoring service (Pingdom, UptimeRobot, etc.)
    Monitoring,
    /// SEO tool (Ahrefs, Semrush, etc.)
    SeoTool,
    /// Security scanner
    SecurityScanner,
    /// Known malicious bot
    Malicious,
    /// Automation tool (curl, wget, scripts)
    Automation,
    /// Headless browser (Puppeteer, Selenium, etc.)
    HeadlessBrowser,
    /// Unknown/unclassified
    #[default]
    Unknown,
}

impl BotCategory {
    /// Returns true if this category is considered a "good" bot.
    pub fn is_good_bot(&self) -> bool {
        matches!(
            self,
            BotCategory::SearchEngine
                | BotCategory::SocialMedia
                | BotCategory::Monitoring
        )
    }

    /// Returns true if this category is considered malicious.
    pub fn is_malicious(&self) -> bool {
        matches!(self, BotCategory::Malicious | BotCategory::SecurityScanner)
    }

    /// Returns the category as a string for headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            BotCategory::Human => "human",
            BotCategory::SearchEngine => "search_engine",
            BotCategory::SocialMedia => "social_media",
            BotCategory::Monitoring => "monitoring",
            BotCategory::SeoTool => "seo_tool",
            BotCategory::SecurityScanner => "security_scanner",
            BotCategory::Malicious => "malicious",
            BotCategory::Automation => "automation",
            BotCategory::HeadlessBrowser => "headless_browser",
            BotCategory::Unknown => "unknown",
        }
    }
}


/// Individual signal scores from each detector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignalBreakdown {
    /// Header analysis score (0-100)
    pub header_score: Option<u8>,

    /// User-agent analysis score (0-100)
    pub user_agent_score: Option<u8>,

    /// Known bot match score (0 = verified good, 100 = verified bad)
    pub known_bot_score: Option<u8>,

    /// Behavioral analysis score (0-100)
    pub behavioral_score: Option<u8>,

    /// Reasons from each detector
    pub reasons: Vec<String>,
}

/// Bot detection result with score and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotScore {
    /// Overall bot probability (0-100)
    /// 0 = definitely human, 100 = definitely bot
    pub score: u8,

    /// Confidence in the score (0.0-1.0)
    pub confidence: f32,

    /// Category classification
    pub category: BotCategory,

    /// Individual signal contributions
    pub signals: SignalBreakdown,

    /// Verified bot name if matched (e.g., "Googlebot")
    pub verified_bot_name: Option<String>,

    /// Whether this is a verified known bot
    pub is_verified: bool,
}

impl Default for BotScore {
    fn default() -> Self {
        Self {
            score: 50,
            confidence: 0.0,
            category: BotCategory::Unknown,
            signals: SignalBreakdown::default(),
            verified_bot_name: None,
            is_verified: false,
        }
    }
}

impl BotScore {
    /// Create a new bot score.
    pub fn new(score: u8, confidence: f32, category: BotCategory) -> Self {
        Self {
            score,
            confidence,
            category,
            signals: SignalBreakdown::default(),
            verified_bot_name: None,
            is_verified: false,
        }
    }

    /// Create a score for a verified good bot.
    pub fn verified_good_bot(name: impl Into<String>, category: BotCategory) -> Self {
        Self {
            score: 0,
            confidence: 1.0,
            category,
            signals: SignalBreakdown::default(),
            verified_bot_name: Some(name.into()),
            is_verified: true,
        }
    }

    /// Create a score for a verified bad/fake bot.
    pub fn verified_bad_bot(reason: impl Into<String>) -> Self {
        let signals = SignalBreakdown {
            known_bot_score: Some(100),
            reasons: vec![reason.into()],
            ..Default::default()
        };

        Self {
            score: 100,
            confidence: 1.0,
            category: BotCategory::Malicious,
            signals,
            verified_bot_name: None,
            is_verified: true,
        }
    }

    /// Create a score for a likely human.
    pub fn likely_human() -> Self {
        Self {
            score: 10,
            confidence: 0.7,
            category: BotCategory::Human,
            signals: SignalBreakdown::default(),
            verified_bot_name: None,
            is_verified: false,
        }
    }

    /// Set the signal breakdown.
    pub fn with_signals(mut self, signals: SignalBreakdown) -> Self {
        self.signals = signals;
        self
    }

    /// Add a reason to the signals.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.signals.reasons.push(reason.into());
        self
    }
}

/// Score calculator that combines signals with weights.
pub struct ScoreCalculator {
    pub header_weight: f32,
    pub user_agent_weight: f32,
    pub known_bot_weight: f32,
    pub behavioral_weight: f32,
}

impl ScoreCalculator {
    /// Create a new score calculator with the given weights.
    pub fn new(
        header_weight: f32,
        user_agent_weight: f32,
        known_bot_weight: f32,
        behavioral_weight: f32,
    ) -> Self {
        Self {
            header_weight,
            user_agent_weight,
            known_bot_weight,
            behavioral_weight,
        }
    }

    /// Calculate the final bot score from individual signals.
    pub fn calculate(&self, signals: &SignalBreakdown) -> BotScore {
        let mut total_weight = 0.0f32;
        let mut weighted_score = 0.0f32;

        // Known bot score is most authoritative
        if let Some(score) = signals.known_bot_score {
            weighted_score += score as f32 * self.known_bot_weight;
            total_weight += self.known_bot_weight;
        }

        if let Some(score) = signals.header_score {
            weighted_score += score as f32 * self.header_weight;
            total_weight += self.header_weight;
        }

        if let Some(score) = signals.user_agent_score {
            weighted_score += score as f32 * self.user_agent_weight;
            total_weight += self.user_agent_weight;
        }

        if let Some(score) = signals.behavioral_score {
            weighted_score += score as f32 * self.behavioral_weight;
            total_weight += self.behavioral_weight;
        }

        let final_score = if total_weight > 0.0 {
            (weighted_score / total_weight).round() as u8
        } else {
            50 // Unknown
        };

        // Calculate confidence based on signal availability
        let max_weight = self.header_weight
            + self.user_agent_weight
            + self.known_bot_weight
            + self.behavioral_weight;
        let confidence = if max_weight > 0.0 {
            (total_weight / max_weight).min(1.0)
        } else {
            0.0
        };

        // Determine category based on score and signals
        let category = self.determine_category(final_score, signals);

        BotScore {
            score: final_score,
            confidence,
            category,
            signals: signals.clone(),
            verified_bot_name: None,
            is_verified: false,
        }
    }

    fn determine_category(&self, score: u8, signals: &SignalBreakdown) -> BotCategory {
        // Check reasons for specific categories
        for reason in &signals.reasons {
            let reason_lower = reason.to_lowercase();
            if reason_lower.contains("headless") || reason_lower.contains("puppeteer") || reason_lower.contains("selenium") {
                return BotCategory::HeadlessBrowser;
            }
            if reason_lower.contains("curl") || reason_lower.contains("wget") || reason_lower.contains("python") {
                return BotCategory::Automation;
            }
            if reason_lower.contains("scanner") || reason_lower.contains("sqlmap") || reason_lower.contains("nikto") {
                return BotCategory::SecurityScanner;
            }
        }

        if score <= 20 {
            BotCategory::Human
        } else if score >= 80 {
            BotCategory::Malicious
        } else {
            BotCategory::Unknown
        }
    }
}

impl Default for ScoreCalculator {
    fn default() -> Self {
        Self {
            header_weight: 0.20,
            user_agent_weight: 0.25,
            known_bot_weight: 0.35,
            behavioral_weight: 0.20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_category_as_str() {
        assert_eq!(BotCategory::Human.as_str(), "human");
        assert_eq!(BotCategory::SearchEngine.as_str(), "search_engine");
        assert_eq!(BotCategory::Malicious.as_str(), "malicious");
    }

    #[test]
    fn test_bot_category_is_good() {
        assert!(BotCategory::SearchEngine.is_good_bot());
        assert!(BotCategory::Monitoring.is_good_bot());
        assert!(!BotCategory::Malicious.is_good_bot());
        assert!(!BotCategory::Human.is_good_bot());
    }

    #[test]
    fn test_score_calculator_no_signals() {
        let calc = ScoreCalculator::default();
        let signals = SignalBreakdown::default();
        let score = calc.calculate(&signals);

        assert_eq!(score.score, 50);
        assert_eq!(score.confidence, 0.0);
    }

    #[test]
    fn test_score_calculator_all_low() {
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
    fn test_score_calculator_all_high() {
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
    fn test_verified_good_bot() {
        let score = BotScore::verified_good_bot("Googlebot", BotCategory::SearchEngine);
        assert_eq!(score.score, 0);
        assert_eq!(score.confidence, 1.0);
        assert!(score.is_verified);
        assert_eq!(score.verified_bot_name, Some("Googlebot".to_string()));
    }

    #[test]
    fn test_verified_bad_bot() {
        let score = BotScore::verified_bad_bot("Fake Googlebot - wrong IP");
        assert_eq!(score.score, 100);
        assert_eq!(score.confidence, 1.0);
        assert!(score.is_verified);
        assert_eq!(score.category, BotCategory::Malicious);
    }
}
