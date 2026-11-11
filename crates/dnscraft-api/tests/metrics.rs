//! `GET /metrics` Prometheus exposition: auth gate + minimal body shape.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;

use dnscraft_api::{AppState, AuthState, Db, ManualClock, Scope, SessionStore, TokenStore};

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
}

fn test_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))
}

async fn setup() -> (axum::Router, String) {
    let clock = clock();
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let sessions = SessionStore::new(db.clone(), IDLE, ABSOLUTE);
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let auth = AuthState::new(sessions, TokenStore::new(db.clone(), MAX_TTL));
    let viewer = tokens
        .create("metrics".into(), "viewer".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let limiter =
        dnscraft_api::RateLimiter::new(dnscraft_api::RateLimitConfig::default(), clock, Vec::new());
    let app = AppState::new()
        .with_rate_limiter(Arc::new(limiter))
        .with_auth(auth);
    let router = app.router().layer(MockConnectInfo(test_addr()));
    (router, viewer.plaintext().expose().to_owned())
}

async fn get_metrics(router: axum::Router, bearer: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().uri("/metrics");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn metrics_requires_authentication() {
    let (router, _) = setup().await;
    let (status, body) = get_metrics(router, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("control_api.auth.unauthenticated"), "{body}");
}

#[tokio::test]
async fn metrics_returns_prometheus_text_for_a_viewer() {
    let (router, token) = setup().await;
    let (status, body) = get_metrics(router, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("dnscraft_up 1"), "{body}");
    assert!(body.contains("# TYPE dnscraft_up gauge"), "{body}");
}
