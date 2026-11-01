//! Shared three-class token-bucket rate limiter with LRU key capping.
//!
//! Used by the control API and MCP crates; each wraps this with its own
//! config/source resolution.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use crate::clock::{Clock, unix_seconds};

/// Which rate-limit bucket a call falls into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketClass {
    /// Read / GET traffic.
    Read,
    /// Mutating / write traffic.
    Write,
    /// Authentication attempts (stricter).
    Auth,
}

/// Steady-state rates (tokens per second) and burst multiplier.
#[derive(Clone, Copy, Debug)]
pub struct Rates {
    /// Read tokens per second.
    pub read: f64,
    /// Write tokens per second.
    pub write: f64,
    /// Auth tokens per second.
    pub auth: f64,
    /// Burst ceiling = rate × this factor (use `1.0` for burst = rate).
    pub burst_factor: f64,
}

impl Rates {
    fn for_class(self, class: BucketClass) -> f64 {
        match class {
            BucketClass::Read => self.read,
            BucketClass::Write => self.write,
            BucketClass::Auth => self.auth,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: f64,
    last: i64,
}

impl TokenBucket {
    fn full(now: i64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn try_consume(&mut self, now: i64, rate: f64, burst: f64) -> Result<(), u64> {
        let elapsed = (now - self.last).max(0) as f64;
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            Err((deficit / rate).ceil().max(1.0) as u64)
        }
    }
}

struct Buckets {
    read: TokenBucket,
    write: TokenBucket,
    auth: TokenBucket,
}

impl Buckets {
    fn new(now: i64, rates: Rates) -> Self {
        let factor = rates.burst_factor.max(1.0);
        Self {
            read: TokenBucket::full(now, rates.read * factor),
            write: TokenBucket::full(now, rates.write * factor),
            auth: TokenBucket::full(now, rates.auth * factor),
        }
    }

    fn bucket_mut(&mut self, class: BucketClass) -> &mut TokenBucket {
        match class {
            BucketClass::Read => &mut self.read,
            BucketClass::Write => &mut self.write,
            BucketClass::Auth => &mut self.auth,
        }
    }
}

struct Entry {
    buckets: Buckets,
    touched: u64,
}

struct LimiterState {
    map: HashMap<String, Entry>,
    order: VecDeque<(String, u64)>,
    seq: u64,
    max_keys: usize,
}

impl LimiterState {
    fn check(&mut self, key: &str, class: BucketClass, now: i64, rates: Rates) -> Result<(), u64> {
        self.seq += 1;
        let seq = self.seq;
        let entry = self.map.entry(key.to_owned()).or_insert_with(|| Entry {
            buckets: Buckets::new(now, rates),
            touched: seq,
        });
        entry.touched = seq;
        self.order.push_back((key.to_owned(), seq));

        let rate = rates.for_class(class).max(1.0);
        let burst = rate * rates.burst_factor.max(1.0);
        let result = entry.buckets.bucket_mut(class).try_consume(now, rate, burst);
        self.evict();
        result
    }

    fn evict(&mut self) {
        while self.map.len() > self.max_keys {
            let Some((key, seq)) = self.order.pop_front() else {
                break;
            };
            if self.map.get(&key).map(|e| e.touched) == Some(seq) {
                self.map.remove(&key);
            }
        }
        if self.order.len() > self.max_keys * 2 {
            self.order = self
                .map
                .iter()
                .map(|(k, e)| (k.clone(), e.touched))
                .collect();
        }
    }

}

/// In-memory token-bucket limiter keyed by an opaque string.
#[derive(Clone)]
pub struct TokenRateLimiter {
    rates: Rates,
    clock: Arc<dyn Clock>,
    state: Arc<Mutex<LimiterState>>,
}

impl TokenRateLimiter {
    /// Creates a limiter with `max_keys` tracked entries (clamped to at least 1).
    pub fn new(rates: Rates, clock: Arc<dyn Clock>, max_keys: usize) -> Self {
        Self {
            rates,
            clock,
            state: Arc::new(Mutex::new(LimiterState {
                map: HashMap::new(),
                order: VecDeque::new(),
                seq: 0,
                max_keys: max_keys.max(1),
            })),
        }
    }

    /// Consumes one token for `key` in `class`; `Err(seconds)` until retry on excess.
    pub fn check(&self, key: &str, class: BucketClass) -> Result<(), u64> {
        let now = unix_seconds(self.clock.now());
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check(key, class, now, self.rates)
    }

    /// Number of currently tracked keys (tests / diagnostics).
    pub fn tracked(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .len()
    }

    /// Sorted list of tracked keys (tests).
    pub fn tracked_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::clock::ManualClock;

    fn limiter(read: f64, write: f64, auth: f64, max: usize) -> (TokenRateLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        (
            TokenRateLimiter::new(
                Rates {
                    read,
                    write,
                    auth,
                    burst_factor: 1.0,
                },
                clock.clone(),
                max,
            ),
            clock,
        )
    }

    #[test]
    fn burst_then_clock_refills() {
        let (limiter, clock) = limiter(2.0, 2.0, 2.0, 8);
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert_eq!(limiter.check("a", BucketClass::Read), Err(1));
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check("a", BucketClass::Read).is_ok());
    }

    #[test]
    fn lru_cap_bounds_tracked_keys() {
        let (limiter, _) = limiter(1.0, 1.0, 1.0, 3);
        for key in ["a", "b", "c", "d", "e"] {
            limiter.check(key, BucketClass::Read).unwrap();
            assert!(limiter.tracked() <= 3);
        }
        assert_eq!(limiter.tracked(), 3);
    }
}
