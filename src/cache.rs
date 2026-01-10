//! Caching utilities for bot detection.

use moka::future::Cache;
use std::hash::Hash;
use std::time::Duration;

/// Generic cache wrapper with statistics.
pub struct DetectionCache<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + 'static,
    V: Clone + Send + Sync + 'static,
{
    inner: Cache<K, V>,
    name: String,
}

impl<K, V> DetectionCache<K, V>
where
    K: Hash + Eq + Send + Sync + Clone + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new cache with the given parameters.
    pub fn new(name: impl Into<String>, max_capacity: u64, ttl: Duration) -> Self {
        let inner = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        Self {
            inner,
            name: name.into(),
        }
    }

    /// Get a value from the cache.
    pub async fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key).await
    }

    /// Insert a value into the cache.
    pub async fn insert(&self, key: K, value: V) {
        self.inner.insert(key, value).await;
    }

    /// Get the current entry count.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// Get the cache name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache: DetectionCache<String, i32> = DetectionCache::new(
            "test",
            100,
            Duration::from_secs(60),
        );

        cache.insert("key1".to_string(), 42).await;

        let value = cache.get(&"key1".to_string()).await;
        assert_eq!(value, Some(42));

        let missing = cache.get(&"missing".to_string()).await;
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        let cache: DetectionCache<String, i32> = DetectionCache::new(
            "test",
            100,
            Duration::from_millis(50), // 50ms TTL
        );

        cache.insert("key".to_string(), 42).await;

        // Should exist immediately
        assert!(cache.get(&"key".to_string()).await.is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be gone
        assert!(cache.get(&"key".to_string()).await.is_none());
    }
}
