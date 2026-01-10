//! Behavioral analysis detector.
//!
//! Analyzes request patterns over time:
//! - Request rate
//! - Timing regularity
//! - Resource access patterns

use super::{DetectionContext, Detector, DetectorResult};
use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Session key for behavioral tracking.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SessionKey {
    /// Client IP address
    pub ip: IpAddr,
}

impl From<IpAddr> for SessionKey {
    fn from(ip: IpAddr) -> Self {
        Self { ip }
    }
}

/// Session data for behavioral analysis.
#[derive(Debug)]
pub struct SessionData {
    /// First request timestamp
    pub first_seen: Instant,
    /// Last request timestamp
    pub last_seen: Instant,
    /// Total request count
    pub request_count: u32,
    /// Recent request timestamps (bounded)
    pub request_times: VecDeque<Instant>,
    /// Unique paths visited (bounded)
    pub paths_visited: std::collections::HashSet<String>,
    /// Maximum paths to track
    max_paths: usize,
    /// Maximum request history
    max_history: usize,
}

impl SessionData {
    /// Create a new session.
    pub fn new(max_history: usize, max_paths: usize) -> Self {
        let now = Instant::now();
        Self {
            first_seen: now,
            last_seen: now,
            request_count: 0,
            request_times: VecDeque::with_capacity(max_history),
            paths_visited: std::collections::HashSet::new(),
            max_paths,
            max_history,
        }
    }

    /// Record a request.
    pub fn record_request(&mut self, path: &str) {
        let now = Instant::now();
        self.last_seen = now;
        self.request_count += 1;

        // Add to request times (bounded)
        if self.request_times.len() >= self.max_history {
            self.request_times.pop_front();
        }
        self.request_times.push_back(now);

        // Add to paths (bounded)
        if self.paths_visited.len() < self.max_paths {
            // Normalize path (remove query string)
            let path_only = path.split('?').next().unwrap_or(path);
            self.paths_visited.insert(path_only.to_string());
        }
    }

    /// Calculate requests per minute.
    pub fn requests_per_minute(&self) -> f64 {
        if self.request_times.len() < 2 {
            return 0.0;
        }

        let first = self.request_times.front().unwrap();
        let last = self.request_times.back().unwrap();
        let duration = last.duration_since(*first);

        if duration.as_secs() == 0 {
            return self.request_times.len() as f64 * 60.0; // Assume all in one second
        }

        (self.request_times.len() as f64 / duration.as_secs_f64()) * 60.0
    }

    /// Calculate timing regularity (coefficient of variation).
    /// Low CV = regular intervals = more bot-like.
    pub fn timing_regularity(&self) -> Option<f64> {
        if self.request_times.len() < 3 {
            return None;
        }

        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..self.request_times.len() {
            let interval = self.request_times[i]
                .duration_since(self.request_times[i - 1])
                .as_secs_f64();
            intervals.push(interval);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean == 0.0 {
            return Some(0.0); // All requests at same time = very regular
        }

        let variance = intervals.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();

        // Coefficient of variation (CV)
        Some(std_dev / mean)
    }

    /// Check if session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Behavioral analyzer detector.
pub struct BehavioralAnalyzer {
    /// Session store
    sessions: Arc<DashMap<SessionKey, SessionData>>,
    /// Maximum sessions to track
    max_sessions: usize,
    /// Session timeout
    session_timeout: Duration,
    /// Requests per minute threshold
    rpm_threshold: u32,
    /// Minimum requests for scoring
    min_requests: u32,
    /// Maximum request history per session
    max_request_history: usize,
    /// Maximum paths to track per session
    max_paths: usize,
    /// Counter for cleanup scheduling
    request_counter: AtomicU64,
}

impl BehavioralAnalyzer {
    /// Create a new behavioral analyzer.
    pub fn new(
        max_sessions: usize,
        session_timeout: Duration,
        rpm_threshold: u32,
        min_requests: u32,
        max_request_history: usize,
    ) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            max_sessions,
            session_timeout,
            rpm_threshold,
            min_requests,
            max_request_history,
            max_paths: 100,
            request_counter: AtomicU64::new(0),
        }
    }

    /// Clean up expired sessions periodically.
    fn maybe_cleanup(&self) {
        let count = self.request_counter.fetch_add(1, Ordering::Relaxed);

        // Cleanup every 1000 requests
        if count % 1000 == 0 {
            self.sessions.retain(|_, v| !v.is_expired(self.session_timeout));
        }
    }

    /// Get or create a session.
    fn get_or_create_session(&self, key: SessionKey) -> dashmap::mapref::one::RefMut<'_, SessionKey, SessionData> {
        // Check if we need to evict
        if self.sessions.len() >= self.max_sessions {
            // Remove a random session (simple eviction)
            if let Some(entry) = self.sessions.iter().next() {
                let key = entry.key().clone();
                drop(entry);
                self.sessions.remove(&key);
            }
        }

        self.sessions.entry(key).or_insert_with(|| {
            SessionData::new(self.max_request_history, self.max_paths)
        })
    }
}

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new(
            100_000,
            Duration::from_secs(3600),
            60,
            5,
            100,
        )
    }
}

#[async_trait]
impl Detector for BehavioralAnalyzer {
    async fn analyze(&self, ctx: &DetectionContext) -> DetectorResult {
        self.maybe_cleanup();

        let key = SessionKey::from(ctx.client_ip);
        let mut session = self.get_or_create_session(key);

        // Record this request
        session.record_request(&ctx.path);

        // Don't score until we have enough data
        if session.request_count < self.min_requests {
            return DetectorResult::new(50)
                .with_reason("insufficient_data".to_string())
                .with_metadata("request_count", session.request_count.to_string());
        }

        let mut score = 0u8;
        let mut result = DetectorResult::new(0);

        // Check requests per minute
        let rpm = session.requests_per_minute();
        if rpm > self.rpm_threshold as f64 {
            let rpm_score = ((rpm / self.rpm_threshold as f64) * 20.0).min(50.0) as u8;
            score = score.saturating_add(rpm_score);
            result = result.with_reason(format!("high_rpm_{:.0}", rpm));
        }
        result = result.with_metadata("rpm", format!("{:.1}", rpm));

        // Check timing regularity
        if let Some(cv) = session.timing_regularity() {
            // CV < 0.1 is very regular (bot-like)
            // CV > 0.5 is irregular (human-like)
            if cv < 0.1 {
                score = score.saturating_add(30);
                result = result.with_reason("very_regular_timing".to_string());
            } else if cv < 0.2 {
                score = score.saturating_add(15);
                result = result.with_reason("regular_timing".to_string());
            }
            result = result.with_metadata("timing_cv", format!("{:.3}", cv));
        }

        // Check path diversity (low diversity = bot-like crawling)
        let path_ratio = session.paths_visited.len() as f64 / session.request_count as f64;
        if session.request_count > 10 {
            if path_ratio > 0.9 {
                // Almost all unique paths = systematic crawling
                score = score.saturating_add(20);
                result = result.with_reason("systematic_crawling".to_string());
            } else if path_ratio < 0.1 {
                // Very few unique paths = normal navigation or polling
                // This is actually human-like behavior
                score = score.saturating_sub(10);
            }
        }
        result = result.with_metadata("path_diversity", format!("{:.2}", path_ratio));

        // Session age vs activity
        let session_age = session.first_seen.elapsed().as_secs();
        if session_age > 0 {
            let requests_per_sec = session.request_count as f64 / session_age as f64;
            if requests_per_sec > 2.0 && session.request_count > 100 {
                score = score.saturating_add(15);
                result = result.with_reason("sustained_high_rate".to_string());
            }
        }

        result.score = score.min(100);
        result = result.with_metadata("request_count", session.request_count.to_string());

        result
    }

    fn name(&self) -> &'static str {
        "behavioral_analyzer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_ctx(ip: &str, path: &str) -> DetectionContext {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), vec!["Test/1.0".to_string()]);
        DetectionContext {
            headers,
            client_ip: ip.parse().unwrap(),
            path: path.to_string(),
            method: "GET".to_string(),
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_initial_requests() {
        let analyzer = BehavioralAnalyzer::default();

        // First few requests should return neutral score
        for i in 0..3 {
            let ctx = make_ctx("192.168.1.1", &format!("/page{}", i));
            let result = analyzer.analyze(&ctx).await;
            assert_eq!(result.score, 50, "Should return neutral score until enough data");
        }
    }

    #[tokio::test]
    async fn test_request_counting() {
        let analyzer = BehavioralAnalyzer::new(1000, Duration::from_secs(60), 60, 2, 100);

        // Send some requests
        for i in 0..5 {
            let ctx = make_ctx("192.168.1.2", &format!("/page{}", i));
            let _ = analyzer.analyze(&ctx).await;
        }

        // Check session was created
        let key = SessionKey::from("192.168.1.2".parse::<IpAddr>().unwrap());
        let session = analyzer.sessions.get(&key).unwrap();
        assert_eq!(session.request_count, 5);
    }

    #[tokio::test]
    async fn test_path_tracking() {
        let analyzer = BehavioralAnalyzer::default();

        // Same path multiple times
        for _ in 0..10 {
            let ctx = make_ctx("192.168.1.3", "/same-page");
            let _ = analyzer.analyze(&ctx).await;
        }

        let key = SessionKey::from("192.168.1.3".parse::<IpAddr>().unwrap());
        let session = analyzer.sessions.get(&key).unwrap();
        assert_eq!(session.paths_visited.len(), 1, "Should track unique paths");
    }

    #[test]
    fn test_timing_regularity() {
        let mut session = SessionData::new(100, 100);

        // Add some request times with regular intervals
        for _ in 0..5 {
            session.request_times.push_back(Instant::now());
            std::thread::sleep(Duration::from_millis(10));
        }

        let cv = session.timing_regularity();
        assert!(cv.is_some());
        // Regular intervals should have low CV
    }
}
