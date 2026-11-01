//! Per-token token-bucket rate limiting for MCP tool calls.
//!
//! Thin wrapper around [`dnscraft_common::rate_limit::TokenRateLimiter`]:
//! burst equals the steady-state rate (`burst_factor = 1`).

use std::sync::Arc;

use crate::config::McpConfig;
use dnscraft_common::clock::Clock;
use dnscraft_common::rate_limit::{Rates, TokenRateLimiter as Shared};

pub(crate) use dnscraft_common::rate_limit::BucketClass;

/// In-memory token-bucket rate limiter keyed by token id or source.
#[derive(Clone)]
pub(crate) struct TokenRateLimiter(Shared);

impl TokenRateLimiter {
    /// Creates a limiter from the validated MCP rate-limit configuration.
    pub(crate) fn new(config: &McpConfig, clock: Arc<dyn Clock>) -> Self {
        Self(Shared::new(
            Rates {
                read: config.read_per_second as f64,
                write: config.write_per_second as f64,
                auth: config.auth_per_second as f64,
                burst_factor: 1.0,
            },
            clock,
            config.max_tracked_tokens,
        ))
    }

    /// Consumes one token for `key` in `class`; `Err(seconds)` until retry on excess.
    pub(crate) fn check(&self, key: &str, class: BucketClass) -> Result<(), u64> {
        self.0.check(key, class)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use dnscraft_common::clock::ManualClock;

    fn config(read: u32, write: u32, auth: u32, max_tracked_tokens: usize) -> McpConfig {
        McpConfig {
            read_per_second: read,
            write_per_second: write,
            auth_per_second: auth,
            max_tracked_tokens,
            ..McpConfig::default()
        }
    }

    fn limiter(read: u32, write: u32, auth: u32) -> (TokenRateLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        (
            TokenRateLimiter::new(&config(read, write, auth, 8), clock.clone()),
            clock,
        )
    }

    #[test]
    fn burst_then_clock_refills_without_sleeping() {
        let (limiter, clock) = limiter(2, 2, 2);
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert_eq!(limiter.check("a", BucketClass::Read), Err(1));
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_err());
    }

    #[test]
    fn buckets_are_independent() {
        let (limiter, _) = limiter(2, 2, 2);
        for _ in 0..2 {
            limiter.check("a", BucketClass::Read).unwrap();
        }
        assert!(limiter.check("a", BucketClass::Read).is_err());
        assert!(limiter.check("a", BucketClass::Write).is_ok());
        assert!(limiter.check("a", BucketClass::Auth).is_ok());
    }

    #[test]
    fn tokens_are_isolated_per_key() {
        let (limiter, _) = limiter(1, 1, 1);
        assert!(limiter.check("token-a", BucketClass::Read).is_ok());
        assert!(limiter.check("token-a", BucketClass::Read).is_err());
        assert!(limiter.check("token-b", BucketClass::Read).is_ok());
        assert!(limiter.check("token-b", BucketClass::Read).is_err());
    }

    #[test]
    fn lru_cap_bounds_tracked_keys() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let limiter = TokenRateLimiter::new(&config(1, 1, 1, 3), clock);
        for key in ["a", "b", "c", "d", "e"] {
            limiter.check(key, BucketClass::Read).unwrap();
            assert!(limiter.0.tracked() <= 3, "cap must hold");
        }
        assert_eq!(limiter.0.tracked(), 3);
    }
}
