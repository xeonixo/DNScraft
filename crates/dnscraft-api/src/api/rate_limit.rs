//! Per-source token-bucket rate limiting for the internal API.
//!
//! A [`RateLimiter`] wraps [`dnscraft_common::rate_limit::TokenRateLimiter`]
//! with control-api config and trusted-proxy source resolution. The
//! [`rate_limit`] middleware rejects with `429` + `control_api.rate_limited`
//! when the bucket is empty.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::RateLimitConfig;
use crate::server::AppState;
use dnscraft_common::clock::Clock;
use dnscraft_common::rate_limit::{Rates, TokenRateLimiter};

/// Default maximum number of distinct sources tracked before LRU eviction.
pub const DEFAULT_MAX_TRACKED_SOURCES: usize = 10_000;

pub(crate) use dnscraft_common::rate_limit::BucketClass;

/// In-memory token-bucket rate limiter keyed by source.
pub struct RateLimiter {
    inner: TokenRateLimiter,
    trusted_proxies: Vec<IpAddr>,
}

impl RateLimiter {
    /// Creates a limiter with the default tracked-source cap.
    pub fn new(
        config: RateLimitConfig,
        clock: Arc<dyn Clock>,
        trusted_proxies: Vec<IpAddr>,
    ) -> Self {
        Self::with_capacity(config, clock, trusted_proxies, DEFAULT_MAX_TRACKED_SOURCES)
    }

    /// Creates a limiter with an explicit tracked-source cap (used by tests).
    pub fn with_capacity(
        config: RateLimitConfig,
        clock: Arc<dyn Clock>,
        trusted_proxies: Vec<IpAddr>,
        max_keys: usize,
    ) -> Self {
        Self {
            inner: TokenRateLimiter::new(
                Rates {
                    read: config.read_per_second as f64,
                    write: config.write_per_second as f64,
                    auth: config.auth_per_second as f64,
                    burst_factor: config.burst_factor as f64,
                },
                clock,
                max_keys,
            ),
            trusted_proxies,
        }
    }

    /// Consumes one token for `key` in `class`; `Err(seconds)` until retry on excess.
    pub(crate) fn check(&self, key: &str, class: BucketClass) -> Result<(), u64> {
        self.inner.check(key, class)
    }
}

/// Resolves the rate-limit source via [`dnscraft_common::net::client_ip_from_forwarded_for`].
fn resolve_source(peer: IpAddr, trusted: &[IpAddr], headers: &HeaderMap) -> IpAddr {
    let xff = headers
        .get(HeaderName::from_static("x-forwarded-for"))
        .and_then(|value| value.to_str().ok());
    dnscraft_common::net::client_ip_from_forwarded_for(peer, trusted, xff)
}

/// The client address for a request: the trusted-proxy rule of
/// [`resolve_source`], shared with handlers that need the caller (login lockout).
pub(crate) fn client_source(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    resolve_source(peer, &state.rate_limiter().trusted_proxies, headers)
}

/// Classifies a request into its rate-limit bucket: auth paths use the auth
/// bucket regardless of method, GET/HEAD are reads, everything else is a write.
pub(crate) fn classify(method: &Method, path: &str) -> BucketClass {
    if path.starts_with("/api/v1/auth") || path.starts_with("/oauth/") {
        BucketClass::Auth
    } else if method == Method::GET || method == Method::HEAD {
        BucketClass::Read
    } else {
        BucketClass::Write
    }
}

/// Rate-limit middleware: resolves the source IP from the trusted peer, picks
/// the bucket class, and rejects with `429` + `control_api.rate_limited` when
/// the source has exhausted its bucket.
///
/// A `401` from `/mcp/v1` is also charged to the auth bucket of its source, so
/// unauthenticated probing cannot avoid the auth limit by using the MCP path.
/// Once that bucket is empty the 401 is replaced by `429`.
pub(crate) async fn rate_limit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let limiter = state.rate_limiter();
    let source = resolve_source(
        peer.ip().to_canonical(),
        &limiter.trusted_proxies,
        req.headers(),
    );
    // Forwarded protocol is honoured only from a trusted proxy (GA10): from any
    // other peer it is removed before a handler can read it.
    if !limiter.trusted_proxies.contains(&peer.ip().to_canonical()) {
        req.headers_mut()
            .remove(HeaderName::from_static("x-forwarded-proto"));
    }
    let class = classify(req.method(), req.uri().path());
    let is_mcp = req.uri().path().starts_with("/mcp/v1");
    match limiter.check(&source.to_string(), class) {
        Ok(()) => {
            let res = next.run(req).await;
            if is_mcp
                && res.status() == StatusCode::UNAUTHORIZED
                && let Err(seconds) = limiter.check(&source.to_string(), BucketClass::Auth)
            {
                return rate_limited_response(seconds);
            }
            res
        }
        Err(seconds) => rate_limited_response(seconds),
    }
}

/// Charges an authenticated principal against its own bucket (GA8). Keys
/// are prefixed so they can never collide with a source IP string.
pub(crate) fn check_principal(
    state: &AppState,
    actor_id: &str,
    method: &Method,
    path: &str,
) -> Result<(), u64> {
    state
        .rate_limiter()
        .check(&format!("principal:{actor_id}"), classify(method, path))
}

/// The `429` envelope with `Retry-After` header and `params.retry_after`.
pub(crate) fn rate_limited_response(seconds: u64) -> Response {
    let mut res = crate::api::response::error_response(
        "control_api.rate_limited",
        Some(serde_json::json!({ "retry_after": seconds })),
        axum::http::StatusCode::TOO_MANY_REQUESTS,
    );
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        res.headers_mut()
            .insert(HeaderName::from_static("retry-after"), value);
    }
    res
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use dnscraft_common::clock::ManualClock;
    use std::time::{Duration, SystemTime};

    fn cfg(per_second: u32, burst_factor: u32) -> RateLimitConfig {
        RateLimitConfig {
            read_per_second: per_second,
            write_per_second: per_second,
            auth_per_second: per_second,
            burst_factor,
        }
    }

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
    }

    #[cfg(test)]
    impl RateLimiter {
        fn tracked_sources(&self) -> usize {
            self.inner.tracked()
        }

        fn tracked_keys(&self) -> Vec<String> {
            self.inner.tracked_keys()
        }
    }

    #[test]
    fn burst_then_clock_refills_without_sleeping() {
        let clock = clock();
        let limiter = RateLimiter::with_capacity(cfg(2, 2), clock.clone(), vec![], 8);
        // Fresh bucket: burst = 2 * 2 = 4 tokens.
        for _ in 0..4 {
            assert!(limiter.check("a", BucketClass::Read).is_ok());
        }
        // Exhausted.
        assert!(limiter.check("a", BucketClass::Read).is_err());
        // One clock second refills 2 tokens — no wall-clock wait.
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_ok());
        assert!(limiter.check("a", BucketClass::Read).is_err());
    }

    #[test]
    fn buckets_are_independent() {
        let limiter = RateLimiter::with_capacity(cfg(2, 2), clock(), vec![], 8);
        for _ in 0..4 {
            limiter.check("a", BucketClass::Read).unwrap();
        }
        assert!(limiter.check("a", BucketClass::Read).is_err());
        // The write and auth buckets are untouched.
        assert!(limiter.check("a", BucketClass::Write).is_ok());
        assert!(limiter.check("a", BucketClass::Auth).is_ok());
    }

    #[test]
    fn lru_cap_bounds_tracked_sources() {
        let limiter = RateLimiter::with_capacity(cfg(1, 1), clock(), vec![], 3);
        for key in ["a", "b", "c", "d", "e"] {
            limiter.check(key, BucketClass::Read).unwrap();
            assert!(limiter.tracked_sources() <= 3, "cap must hold");
        }
        assert_eq!(limiter.tracked_sources(), 3);
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let clock = clock();
        let limiter = RateLimiter::with_capacity(cfg(1, 1), clock.clone(), vec![], 2);
        limiter.check("a", BucketClass::Read).unwrap();
        limiter.check("b", BucketClass::Read).unwrap();
        // Touch "a" so "b" becomes the least-recently-used.
        clock.advance(Duration::from_secs(1));
        limiter.check("a", BucketClass::Read).unwrap();
        // Inserting "c" evicts "b", keeps "a".
        limiter.check("c", BucketClass::Read).unwrap();
        assert_eq!(
            limiter.tracked_keys(),
            vec!["a".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn resolve_source_ignores_forwarded_header_from_untrusted_peer() {
        let peer = "203.0.113.5".parse::<IpAddr>().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("198.51.100.7"),
        );
        assert_eq!(resolve_source(peer, &[], &headers), peer);
    }

    #[test]
    fn resolve_source_honours_forwarded_header_from_trusted_proxy() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let trusted: Vec<IpAddr> = vec![peer];
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("198.51.100.7, 10.0.0.1"),
        );
        assert_eq!(
            resolve_source(peer, &trusted, &headers),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_source_ignores_spoofed_leftmost_entries() {
        // The client prepended a fake address; the proxy appended the real one.
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let trusted: Vec<IpAddr> = vec![peer];
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("192.0.2.66, 198.51.100.7, 10.0.0.1"),
        );
        assert_eq!(
            resolve_source(peer, &trusted, &headers),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_source_skips_chained_trusted_proxies() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let inner = "10.0.0.2".parse::<IpAddr>().unwrap();
        let trusted: Vec<IpAddr> = vec![peer, inner];
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("198.51.100.7, 10.0.0.2, 10.0.0.1"),
        );
        assert_eq!(
            resolve_source(peer, &trusted, &headers),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_source_falls_back_to_peer_when_every_entry_is_trusted() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let trusted: Vec<IpAddr> = vec![peer];
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("10.0.0.1, 10.0.0.1"),
        );
        assert_eq!(resolve_source(peer, &trusted, &headers), peer);
    }

    #[test]
    fn resolve_source_falls_back_to_peer_on_malformed_header() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let trusted: Vec<IpAddr> = vec![peer];
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("not-an-ip"),
        );
        assert_eq!(resolve_source(peer, &trusted, &headers), peer);
    }

    #[test]
    fn principal_bucket_is_separate_from_source_bucket() {
        let state = AppState::new().with_rate_limiter(Arc::new(RateLimiter::with_capacity(
            cfg(2, 2),
            clock(),
            Vec::new(),
            8,
        )));
        for _ in 0..4 {
            check_principal(&state, "alice", &Method::GET, "/api/v1/status").unwrap();
        }
        assert!(check_principal(&state, "alice", &Method::GET, "/api/v1/status").is_err());
        // Another principal and the source bucket are unaffected.
        check_principal(&state, "bob", &Method::GET, "/api/v1/status").unwrap();
        assert!(
            state
                .rate_limiter()
                .check("127.0.0.1", BucketClass::Read)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mcp_probing_is_throttled_by_the_auth_bucket() {
        use axum::Router;
        use axum::body::Body;
        use axum::extract::connect_info::MockConnectInfo;
        use axum::middleware;
        use axum::routing::get;
        use tower::ServiceExt as _;

        // Reads are plentiful; only the auth bucket (burst 1) is tight. Each
        // 401 from /mcp/v1 is charged to it, so the second probe is throttled.
        let config = RateLimitConfig {
            read_per_second: 100,
            write_per_second: 100,
            auth_per_second: 1,
            burst_factor: 1,
        };
        let limiter = RateLimiter::with_capacity(config, clock(), Vec::new(), 8);
        let state = AppState::new().with_rate_limiter(Arc::new(limiter));
        let app = Router::new()
            .route(
                "/mcp/v1",
                get(|| async { StatusCode::UNAUTHORIZED.into_response() }),
            )
            .layer(middleware::from_fn_with_state(state, rate_limit))
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        let probe = || {
            Request::builder()
                .uri("/mcp/v1")
                .body(Body::empty())
                .unwrap()
        };
        let first = app.clone().oneshot(probe()).await.unwrap();
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let second = app.oneshot(probe()).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn forwarded_proto_is_stripped_from_untrusted_peers_only() {
        use axum::body::Body;
        use axum::extract::connect_info::MockConnectInfo;
        use axum::middleware;
        use axum::routing::get;
        use axum::{Router, http::Request};
        use tower::ServiceExt as _;

        async fn echo(headers: HeaderMap) -> String {
            headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("none")
                .to_owned()
        }
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let state = |trusted: Vec<IpAddr>| {
            AppState::new().with_rate_limiter(Arc::new(RateLimiter::with_capacity(
                cfg(10, 2),
                clock(),
                trusted,
                8,
            )))
        };
        let read = |trusted: Vec<IpAddr>| {
            let app = Router::new()
                .route("/x", get(echo))
                .layer(middleware::from_fn_with_state(state(trusted), rate_limit))
                .layer(MockConnectInfo(SocketAddr::new(peer, 1)));
            async move {
                let req = Request::builder()
                    .uri("/x")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap();
                let bytes = axum::body::to_bytes(app.oneshot(req).await.unwrap().into_body(), 64)
                    .await
                    .unwrap();
                String::from_utf8(bytes.to_vec()).unwrap()
            }
        };
        assert_eq!(read(Vec::new()).await, "none");
        assert_eq!(read(vec![peer]).await, "https");
    }

    #[test]
    fn classify_maps_method_and_path() {
        assert_eq!(classify(&Method::GET, "/api/v1/status"), BucketClass::Read);
        assert_eq!(classify(&Method::HEAD, "/api/v1/status"), BucketClass::Read);
        assert_eq!(classify(&Method::PUT, "/api/v1/config"), BucketClass::Write);
        assert_eq!(
            classify(&Method::POST, "/api/v1/auth/login"),
            BucketClass::Auth
        );
        assert_eq!(
            classify(&Method::GET, "/api/v1/auth/tokens"),
            BucketClass::Auth
        );
    }
}
