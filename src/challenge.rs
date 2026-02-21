//! Challenge token system for bot verification.
//!
//! Generates and verifies HMAC-signed challenge tokens.

use crate::config::ChallengeType;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Challenge manager for generating and verifying tokens.
pub struct ChallengeManager {
    /// Secret key for HMAC signing
    secret: Vec<u8>,
    /// Token validity duration in seconds
    validity_seconds: u64,
    /// Cookie name for storing tokens
    pub cookie_name: String,
    /// Default challenge type
    pub default_type: ChallengeType,
    /// JavaScript challenge URL
    pub js_challenge_url: Option<String>,
    /// CAPTCHA challenge URL
    pub challenge_url: Option<String>,
}

impl ChallengeManager {
    /// Create a new challenge manager.
    pub fn new(
        secret: impl Into<String>,
        validity_seconds: u64,
        cookie_name: impl Into<String>,
        default_type: ChallengeType,
        js_challenge_url: Option<String>,
        challenge_url: Option<String>,
    ) -> Self {
        Self {
            secret: secret.into().into_bytes(),
            validity_seconds,
            cookie_name: cookie_name.into(),
            default_type,
            js_challenge_url,
            challenge_url,
        }
    }

    /// Generate a challenge token.
    ///
    /// Token format: `{timestamp}|{nonce}|{hmac}`
    pub fn generate_token(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX epoch")
            .as_secs();

        let nonce = self.generate_nonce();
        let data = format!("{}|{}", timestamp, nonce);
        let signature = self.sign(&data);

        format!("{}|{}", data, signature)
    }

    /// Verify a challenge token.
    ///
    /// Returns true if the token is valid and not expired.
    pub fn verify_token(&self, token: &str) -> bool {
        let parts: Vec<&str> = token.split('|').collect();
        if parts.len() != 3 {
            return false;
        }

        let timestamp: u64 = match parts[0].parse() {
            Ok(ts) => ts,
            Err(_) => return false,
        };

        let nonce = parts[1];
        let provided_signature = parts[2];

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX epoch")
            .as_secs();

        // Use >= to ensure 0 validity means immediately expired
        if now.saturating_sub(timestamp) >= self.validity_seconds && self.validity_seconds == 0 {
            return false;
        }
        if now.saturating_sub(timestamp) > self.validity_seconds {
            return false;
        }

        // Verify signature
        let data = format!("{}|{}", timestamp, nonce);
        let expected_signature = self.sign(&data);

        // Constant-time comparison
        self.constant_time_eq(provided_signature.as_bytes(), expected_signature.as_bytes())
    }

    /// Extract token from cookie header.
    pub fn extract_token_from_cookies(&self, cookie_header: &str) -> Option<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(value) = cookie.strip_prefix(&format!("{}=", self.cookie_name)) {
                return Some(value.to_string());
            }
        }
        None
    }

    /// Get challenge parameters for the decision response.
    pub fn get_challenge_params(&self, challenge_type: &ChallengeType) -> HashMap<String, String> {
        let mut params = HashMap::new();

        match challenge_type {
            ChallengeType::JavaScript => {
                if let Some(url) = &self.js_challenge_url {
                    params.insert("challenge_url".to_string(), url.clone());
                }
                params.insert("token".to_string(), self.generate_token());
                params.insert("cookie_name".to_string(), self.cookie_name.clone());
            }
            ChallengeType::Captcha => {
                if let Some(url) = &self.challenge_url {
                    params.insert("challenge_url".to_string(), url.clone());
                }
                params.insert("token".to_string(), self.generate_token());
            }
            ChallengeType::ProofOfWork => {
                params.insert("difficulty".to_string(), "4".to_string()); // 4 leading zeros
                params.insert("token".to_string(), self.generate_token());
            }
        }

        params
    }

    /// Generate a random nonce.
    fn generate_nonce(&self) -> String {
        use std::time::Instant;
        // Simple nonce using timestamp + random-ish value
        // In production, use a proper random generator
        let instant = Instant::now();
        let nanos = instant.elapsed().as_nanos();
        format!("{:x}{:x}", nanos, std::process::id())
    }

    /// Sign data with HMAC-SHA256.
    fn sign(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Constant-time string comparison to prevent timing attacks.
    fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new(
            "default-secret-change-me",
            300, // 5 minutes
            "_zentinel_bot_check",
            ChallengeType::JavaScript,
            Some("/_zentinel/challenge.js".to_string()),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let manager = ChallengeManager::default();
        let token = manager.generate_token();

        assert!(!token.is_empty());
        assert_eq!(token.split('|').count(), 3);
    }

    #[test]
    fn test_token_verification() {
        let manager = ChallengeManager::default();
        let token = manager.generate_token();

        assert!(manager.verify_token(&token), "Fresh token should be valid");
    }

    #[test]
    fn test_invalid_token() {
        let manager = ChallengeManager::default();

        assert!(!manager.verify_token("invalid"), "Invalid token should fail");
        assert!(!manager.verify_token("a|b|c"), "Wrong signature should fail");
        assert!(!manager.verify_token(""), "Empty token should fail");
    }

    #[test]
    fn test_expired_token() {
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
    fn test_cookie_extraction() {
        let manager = ChallengeManager::new(
            "secret",
            300,
            "bot_check",
            ChallengeType::JavaScript,
            None,
            None,
        );

        let cookies = "session=abc123; bot_check=token_value; other=xyz";
        let token = manager.extract_token_from_cookies(cookies);
        assert_eq!(token, Some("token_value".to_string()));

        let no_cookie = "session=abc123; other=xyz";
        let token = manager.extract_token_from_cookies(no_cookie);
        assert_eq!(token, None);
    }

    #[test]
    fn test_challenge_params() {
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
    }

    #[test]
    fn test_constant_time_eq() {
        let manager = ChallengeManager::default();

        assert!(manager.constant_time_eq(b"hello", b"hello"));
        assert!(!manager.constant_time_eq(b"hello", b"world"));
        assert!(!manager.constant_time_eq(b"hello", b"hell"));
    }
}
