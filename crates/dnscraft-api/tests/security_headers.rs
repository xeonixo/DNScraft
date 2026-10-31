//! Baseline response headers on every response, and the anonymous/authenticated
//! split of `GET /api/v1/status`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, AuthState, Db, ManualClock, Scope, SessionStore, TlsMode, TlsStatus,
    TlsStatusProvider, TokenStore,
};

const HSTS: &str = "max-age=31536000; includeSubDomains";
const DAY: Duration = Duration::from_secs(24 * 3600);

struct FakeTls;

impl TlsStatusProvider for FakeTls {
    fn status(&self) -> TlsStatus {
        TlsStatus::new(TlsMode::Acme, "cd".repeat(32))
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40_000))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_with(uri: &str, name: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(name, value)
        .body(Body::empty())
        .unwrap()
}

async fn call(
    state: AppState,
    from: SocketAddr,
    req: Request<Body>,
) -> (StatusCode, HeaderMap, Value) {
    let router: Router = state.router().layer(MockConnectInfo(from));
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn api_responses_carry_the_baseline_headers_and_no_hsts_over_plain_http() {
    let (status, h, _) = call(AppState::new(), loopback(), get("/api/v1/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-frame-options"], "DENY");
    assert!(h.get("strict-transport-security").is_none());
}

#[tokio::test]
async fn error_envelopes_outside_the_handlers_carry_the_headers_too() {
    let (status, h, _) = call(AppState::new(), loopback(), get("/api/v1/no-such-route")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["cache-control"], "no-store");
}

#[tokio::test]
async fn non_api_paths_get_nosniff_and_referrer_but_no_no_store_or_frame_deny() {
    let (status, h, _) = call(AppState::new(), loopback(), get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h.get("cache-control").is_none());
    assert!(h.get("x-frame-options").is_none());
}

#[tokio::test]
async fn hsts_is_sent_over_tls_or_from_a_trusted_proxy_that_forwards_https() {
    let (_, h, _) = call(
        AppState::new().with_tls(Arc::new(FakeTls)),
        loopback(),
        get("/api/v1/status"),
    )
    .await;
    assert_eq!(h["strict-transport-security"], HSTS);

    let forwarded = || get_with("/api/v1/status", "x-forwarded-proto", "https");
    let proxied = AppState::new().with_trusted_proxies(vec![IpAddr::from([127, 0, 0, 1])]);
    let (_, h, _) = call(proxied, loopback(), forwarded()).await;
    assert_eq!(h["strict-transport-security"], HSTS);

    // The same header from an untrusted peer is ignored.
    let (_, h, _) = call(AppState::new(), loopback(), forwarded()).await;
    assert!(h.get("strict-transport-security").is_none());
}

#[tokio::test]
async fn status_is_minimal_for_anonymous_and_full_for_an_authenticated_caller() {
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let db = Db::open_in_memory(clock).await.unwrap();
    let store = TokenStore::new(db.clone(), 365 * DAY);
    let viewer = store
        .create("v".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(db.clone(), Duration::from_secs(3600), 12 * DAY),
        TokenStore::new(db.clone(), 365 * DAY),
    );
    let state = AppState::new().with_auth(auth).with_tls(Arc::new(FakeTls));

    let (status, _, anon) = call(state.clone(), loopback(), get("/api/v1/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        anon["data"],
        json!({ "ready": true, "modules_not_ready": [] })
    );

    let bogus = get_with("/api/v1/status", "authorization", "Bearer not-a-real-token");
    let (_, _, still_anon) = call(state.clone(), loopback(), bogus).await;
    assert_eq!(still_anon["data"], anon["data"]);

    let bearer = format!("Bearer {}", viewer.plaintext().expose());
    let (status, _, full) = call(
        state,
        loopback(),
        get_with("/api/v1/status", "authorization", &bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(full["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(full["data"]["tls_mode"], "acme");
    assert_eq!(full["data"]["ready"], true);
}
