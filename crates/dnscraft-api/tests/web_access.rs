//! Public web access opt-in (`/api/v1/web-access`): stored in the config snapshot and pushed live
//! into the listeners' web hand-off.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use dnscraft_api::{
    AppState, Audit, AuthState, BannedSource, ConfigService, ConfigStore, Db, LocalAccountStore,
    ManualClock, ModuleAppliers, Role, Scope, SessionStore, TokenStore, WebBans,
};
use dnscraft_listeners::WebSlot;
use serde_json::{Value, json};
use tower::ServiceExt as _;

async fn call(
    state: &AppState,
    method: Method,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            9,
        ))));
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = router.oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn web_access_is_off_by_default_and_applies_live() {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let slot = Arc::new(WebSlot::default());
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers {
            web: Some(slot.clone()),
            ..ModuleAppliers::default()
        },
        "node-a",
    );
    let sessions = SessionStore::new(
        db.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(12 * 3600),
    );
    let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
    let local = LocalAccountStore::new(db.clone(), 5, Duration::from_secs(900));
    local
        .upsert("admin", "a-strong-password", Role::Admin)
        .await
        .unwrap();
    let admin = tokens
        .create(
            "admin".to_owned(),
            "admin-token".to_owned(),
            Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let bearer = admin.plaintext().expose().to_owned();
    let auth = AuthState::new(sessions, tokens).with_local_accounts(local);
    let state = AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_auth(auth)
        .with_config_service(Arc::new(service));

    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/web-access",
        None,
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["public_enabled"], false);
    assert_eq!(body["data"]["allowed_cidrs"], json!([]));
    assert!(!slot.public());
    assert!(slot.allows_public_cidr("203.0.113.9".parse().unwrap()));

    let put = |enabled: Value| json!({ "public_enabled": enabled });
    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(put(json!(true))),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(slot.public());
    let (_, body) = call(
        &state,
        Method::GET,
        "/api/v1/web-access",
        None,
        Some(&bearer),
    )
    .await;
    assert_eq!(body["data"]["public_enabled"], true);

    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(put(json!(false))),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!slot.public());

    let (status, _) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(put(json!("yes"))),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn web_access_cidr_allowlist_applies_live_and_rejects_bad_entries() {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let slot = Arc::new(WebSlot::default());
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers {
            web: Some(slot.clone()),
            ..ModuleAppliers::default()
        },
        "node-a",
    );
    let sessions = SessionStore::new(
        db.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(12 * 3600),
    );
    let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
    let local = LocalAccountStore::new(db.clone(), 5, Duration::from_secs(900));
    local
        .upsert("admin", "a-strong-password", Role::Admin)
        .await
        .unwrap();
    let admin = tokens
        .create(
            "admin".to_owned(),
            "admin-token".to_owned(),
            Scope::Admin,
            None,
        )
        .await
        .unwrap();
    let bearer = admin.plaintext().expose().to_owned();
    let state = AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_auth(AuthState::new(sessions, tokens).with_local_accounts(local))
        .with_config_service(Arc::new(service));

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(json!({
            "public_enabled": true,
            "allowed_cidrs": ["203.0.113.0/24", " 2001:db8::/32 "]
        })),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(slot.public());
    assert!(slot.allows_public_cidr("203.0.113.9".parse().unwrap()));
    assert!(slot.allows_public_cidr("2001:db8::1".parse().unwrap()));
    assert!(!slot.allows_public_cidr("198.51.100.1".parse().unwrap()));
    assert_eq!(
        body["data"]["allowed_cidrs"],
        json!(["203.0.113.0/24", "2001:db8::/32"])
    );

    let (status, body) = call(
        &state,
        Method::GET,
        "/api/v1/web-access",
        None,
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["public_enabled"], true);
    assert_eq!(
        body["data"]["allowed_cidrs"],
        json!(["203.0.113.0/24", "2001:db8::/32"])
    );

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(json!({
            "public_enabled": true,
            "allowed_cidrs": ["not-a-cidr"]
        })),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "control_api.config.invalid");
    assert!(slot.allows_public_cidr("203.0.113.9".parse().unwrap()));
    assert!(!slot.allows_public_cidr("198.51.100.1".parse().unwrap()));
}

#[tokio::test]
async fn web_access_refuses_public_without_auth() {
    let clock = Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    let state = AppState::new()
        .with_clock(clock)
        .with_db(db)
        .with_config_service(Arc::new(service));

    let (status, body) = call(
        &state,
        Method::PUT,
        "/api/v1/web-access",
        Some(json!({ "public_enabled": true })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"]["code"],
        "control_api.web_access.bootstrap_auth"
    );
}

struct FakeBans(std::sync::Mutex<Vec<BannedSource>>);

impl WebBans for FakeBans {
    fn banned(&self) -> Vec<BannedSource> {
        self.0.lock().unwrap().clone()
    }
    fn unban(&self, ip: std::net::IpAddr) -> bool {
        let mut list = self.0.lock().unwrap();
        let before = list.len();
        list.retain(|b| b.ip != ip);
        list.len() != before
    }
}

#[tokio::test]
async fn web_bans_list_sorted_and_unban() {
    let state = AppState::new().with_web_bans(Arc::new(FakeBans(std::sync::Mutex::new(vec![
        BannedSource {
            ip: "203.0.113.9".parse().unwrap(),
            until_unix: 2_000,
        },
        BannedSource {
            ip: "198.51.100.7".parse().unwrap(),
            until_unix: 1_000,
        },
    ]))));
    let (status, body) = call(&state, Method::GET, "/api/v1/web-bans", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items[0]["ip"], "198.51.100.7");
    assert_eq!(items.len(), 2);

    let (status, _) = call(
        &state,
        Method::DELETE,
        "/api/v1/web-bans/198.51.100.7",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &state,
        Method::DELETE,
        "/api/v1/web-bans/198.51.100.7",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &state,
        Method::DELETE,
        "/api/v1/web-bans/not-an-ip",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
