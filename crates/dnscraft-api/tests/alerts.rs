//! `GET /api/v1/alerts` assembles active problems from the live module state
//! the control-api already holds (TLS, readiness, listeners, cluster, clients,
//! query-log sink, backups, update cache). Stubs mirror the production adapters.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, AuthState, ClientDirectory, ClusterStatus, ClusterStatusHandle, ClusterStore,
    ConfigActor, ConfigService, ConfigStore, Db, DirectoryClient, DirectoryHealth,
    ListenersStatusProvider, ManualClock, ModuleAppliers, QueryLog, QueryLogConfig, Scope,
    SessionStore, StoreHealth, SyncSummary, TlsMode, TlsStatus, TlsStatusProvider, TokenStore,
};
use dnscraft_cluster::StatusWarning;
use dnscraft_filtering::{BlockMode, ListId, Reason, RuleSource, SetId};
use dnscraft_listeners::{
    ListenerStatus, ListenersError, ListenersStatus, Protocol, QueryEvent, QueryEventSink,
};
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, DnsProtocol, FilterHit,
    ListenerId, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Name, Rcode, RecordType};
use dnscraft_resolver::{DnssecStatus, Query};

const NOW: u64 = 1_700_000_000;
const TOKEN_TTL: Duration = Duration::from_secs(900);

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// A TLS provider reporting a fixed status.
struct FixedTls(TlsStatus);

impl TlsStatusProvider for FixedTls {
    fn status(&self) -> TlsStatus {
        self.0.clone()
    }
}

struct FixedListeners(ListenersStatus);

impl ListenersStatusProvider for FixedListeners {
    fn listeners_status(&self) -> ListenersStatus {
        self.0.clone()
    }
}

struct FixedClients(DirectoryHealth);

#[async_trait::async_trait]
impl ClientDirectory for FixedClients {
    fn clients(&self) -> Vec<DirectoryClient> {
        Vec::new()
    }

    async fn sync(&self) -> Result<SyncSummary, dnscraft_api::ControlApiError> {
        Ok(SyncSummary {
            generation: 1,
            rebuilt: false,
            client_count: 0,
            ip_conflicts: self.0.ip_conflicts,
        })
    }

    fn health(&self) -> DirectoryHealth {
        self.0.clone()
    }
}

async fn get_alerts(state: AppState, bearer: &str) -> (StatusCode, Value) {
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let req = Request::builder()
        .uri("/api/v1/alerts")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn alert_ids(body: &Value) -> Vec<&str> {
    body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect()
}

async fn base_state() -> (AppState, String, Arc<ManualClock>, Db) {
    let clock = Arc::new(ManualClock::new(at(NOW)));
    let db = Db::open_in_memory(Arc::clone(&clock) as _).await.unwrap();
    let tokens = TokenStore::new(db.clone(), Duration::from_secs(3600));
    let viewer = tokens
        .create("ops".into(), "dash".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(
            db.clone(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
        ),
        tokens,
    );
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    let state = AppState::new()
        .with_clock(Arc::clone(&clock) as _)
        .with_db(db.clone())
        .with_auth(auth)
        .with_config_service(Arc::new(service));
    (state, viewer.plaintext().expose().to_owned(), clock, db)
}

fn loggable_event(secs: u64) -> QueryEvent {
    let selection = SelectionCause::Subnet {
        network: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        prefix_len: 24,
    };
    QueryEvent {
        time: at(secs),
        protocol: DnsProtocol::Udp53,
        listener_id: ListenerId::new("dns").unwrap(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        peer_ip: None,
        client_id: None,
        query: Query {
            name: Name::from_ascii("ads.example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::IN,
        },
        rcode: Rcode::NXDOMAIN,
        answer_size: 64,
        answers: Vec::new(),
        duration: Duration::from_millis(1),
        decision: DecisionRecord {
            view_id: ViewId::new("default").unwrap(),
            profile_id: ProfileId::new("default").unwrap(),
            selection,
            client_id: None,
            client_label: None,
            client_device: None,
            filter_set: SetId::new("default").unwrap(),
            steps: vec![
                DecisionStep::Selected { cause: selection },
                DecisionStep::FilterBlocked,
            ],
            filter: Some(FilterHit {
                reason: Reason {
                    rule: Arc::from("||ads.example^"),
                    source: RuleSource::List {
                        list: ListId::new("test-list").unwrap(),
                        line: 1,
                    },
                    important: false,
                },
                block_mode: Some(BlockMode::NxDomain),
            }),
            forward_zone: None,
            dnssec: Some(DnssecStatus::Indeterminate),
            answer_source: AnswerOrigin::Filter,
            timings: DecisionTimings {
                select_us: 1,
                filter_us: 1,
                resolve_us: 0,
                total_us: 2,
            },
            rcode: Rcode::NXDOMAIN,
        },
        loggable: true,
    }
}

#[tokio::test]
async fn no_alerts_gives_an_empty_list_for_a_viewer() {
    let (state, viewer, _, _) = base_state().await;
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["active_count"], 0);
    assert!(body["data"]["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_certificate_inside_the_renewal_window_is_one_warning() {
    let (state, viewer, _, _) = base_state().await;
    let mut tls = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
    tls.cert_expiring = true;
    tls.days_to_expiry = Some(12);
    let state = state.with_tls(Arc::new(FixedTls(tls)));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["active_count"], 1);
    let item = &body["data"]["items"][0];
    assert_eq!(item["id"], "tls.cert.expiring");
    assert_eq!(item["severity"], "warning");
    assert_eq!(item["module"], "tls");
    assert_eq!(item["params"]["days_to_expiry"], 12);
    assert_eq!(item["target_route"], "/tls");
}

#[tokio::test]
async fn a_self_signed_bootstrap_raises_a_warning() {
    let (state, viewer, _, _) = base_state().await;
    let tls = TlsStatus::new(TlsMode::SelfSigned, "00".repeat(32));
    let state = state.with_tls(Arc::new(FixedTls(tls)));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(alert_ids(&body).contains(&"tls.bootstrap.self_signed"));
}

#[tokio::test]
async fn not_ready_modules_raise_a_critical_alert() {
    let (state, viewer, _, _) = base_state().await;
    state.readiness().expect_module("resolver");
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["active_count"], 1);
    let item = &body["data"]["items"][0];
    assert_eq!(item["id"], "system.not_ready");
    assert_eq!(item["severity"], "critical");
    assert_eq!(item["params"]["modules"][0], "resolver");
}

#[tokio::test]
async fn a_listener_bind_failure_is_critical() {
    let (state, viewer, _, _) = base_state().await;
    let listeners = ListenersStatus {
        listeners: vec![ListenerStatus {
            id: ListenerId::new("dns").unwrap(),
            protocol: Protocol::Udp53,
            configured_address: SocketAddr::from(([0, 0, 0, 0], 53)),
            bound: None,
            error: Some(ListenersError::Bind {
                address: "0.0.0.0:53".to_owned(),
                message: "address already in use".to_owned(),
            }),
            connections: 0,
            queries: 0,
            answered: 0,
            dropped: 0,
            rate_limited: 0,
            banned_sources: 0,
            tls_no_cert: 0,
            tls_handshake_failures: 0,
        }],
        events_dropped: 0,
        ban_entries: 0,
    };
    let state = state.with_listeners_status(Arc::new(FixedListeners(listeners)));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let item = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "listeners.bind_failed")
        .expect("bind_failed alert");
    assert_eq!(item["severity"], "critical");
    assert_eq!(item["params"]["listener_id"], "dns");
    assert_eq!(item["params"]["code"], "listeners.bind");
    assert_eq!(item["target_route"], "/listeners");
}

#[tokio::test]
async fn cluster_sub_node_problems_come_from_status_handle() {
    let (state, viewer, _, _) = base_state().await;
    let handle = Arc::new(ClusterStatusHandle::new());
    handle.set(ClusterStatus {
        role: "sub_node".to_owned(),
        node_id: "node-b".to_owned(),
        master_reachable: false,
        applied_version: Some(3),
        lag: 2,
        queue_depth: 4,
        last_sync: None,
        degraded_nodes: 0,
        last_apply_error: Some("policy.config.invalid".to_owned()),
        warnings: vec![
            StatusWarning {
                code: "cluster.clock_skew".to_owned(),
                params: Some(json!({ "skew_seconds": 12 })),
            },
            StatusWarning {
                code: "cluster.config.stale".to_owned(),
                params: None,
            },
        ],
    });
    let state = state.with_cluster_status(handle);
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = alert_ids(&body);
    for expected in [
        "cluster.master.unreachable",
        "cluster.config.lag",
        "cluster.apply_failed",
        "cluster.clock_skew",
        "cluster.config.stale",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
    let lag = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "cluster.config.lag")
        .unwrap();
    assert_eq!(lag["params"]["lag"], 2);
}

#[tokio::test]
async fn master_reports_degraded_sync_and_fresh_disconnected_nodes() {
    let (state, viewer, clock, _) = base_state().await;
    let store = ClusterStore::open_in_memory(Arc::clone(&clock) as _, TOKEN_TTL)
        .await
        .unwrap();
    store
        .register_node("node-b", &"ab".repeat(32))
        .await
        .unwrap();
    let handle = Arc::new(ClusterStatusHandle::new());
    handle.set(ClusterStatus {
        role: "master".to_owned(),
        node_id: "master".to_owned(),
        master_reachable: true,
        applied_version: Some(10),
        lag: 0,
        queue_depth: 0,
        last_sync: Some(at(NOW)),
        degraded_nodes: 2,
        last_apply_error: None,
        warnings: Vec::new(),
    });
    let state = state
        .with_cluster_role(dnscraft_cluster::Role::Master)
        .with_cluster_store(Arc::new(store))
        .with_cluster_status(handle);
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = alert_ids(&body);
    assert!(ids.contains(&"cluster.sync.degraded"), "{ids:?}");
    assert!(ids.contains(&"cluster.node.disconnected"), "{ids:?}");
    let disconnected = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "cluster.node.disconnected")
        .unwrap();
    assert_eq!(disconnected["params"]["node_id"], "node-b");
}

#[tokio::test]
async fn master_reports_quiet_nodes_as_offline_after_five_minutes() {
    let (state, viewer, clock, _) = base_state().await;
    let store = ClusterStore::open_in_memory(Arc::clone(&clock) as _, TOKEN_TTL)
        .await
        .unwrap();
    store
        .register_node("node-quiet", &"cd".repeat(32))
        .await
        .unwrap();
    clock.advance(Duration::from_secs(301));
    let state = state
        .with_cluster_role(dnscraft_cluster::Role::Master)
        .with_cluster_store(Arc::new(store));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = alert_ids(&body);
    assert!(ids.contains(&"cluster.node.offline"), "{ids:?}");
    assert!(
        !ids.contains(&"cluster.node.disconnected"),
        "offline replaces the short disconnect window: {ids:?}"
    );
}

#[tokio::test]
async fn unifi_sync_failure_and_ip_conflicts_raise_client_alerts() {
    let (state, viewer, _, _) = base_state().await;
    let state = state.with_clients(Arc::new(FixedClients(DirectoryHealth {
        last_error: Some("clients.sync.unreachable"),
        ip_conflicts: 3,
    })));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = alert_ids(&body);
    assert!(ids.contains(&"clients.unifi.sync_failed"), "{ids:?}");
    assert!(ids.contains(&"clients.unifi.ip_conflicts"), "{ids:?}");
    let conflicts = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "clients.unifi.ip_conflicts")
        .unwrap();
    assert_eq!(conflicts["params"]["count"], 3);
}

#[tokio::test]
async fn query_log_sink_drops_raise_an_alert() {
    let (state, viewer, _, db) = base_state().await;
    let (sink, _rx) = QueryLog::channel(1);
    let log = Arc::new(QueryLog::new(db, QueryLogConfig::default(), "node-a").with_sink(sink.clone()));
    // Capacity 1 and no consumer: the first send fills the channel; later ones drop.
    assert!(sink.try_send(loggable_event(NOW)));
    assert!(!sink.try_send(loggable_event(NOW + 1)));
    assert!(!sink.try_send(loggable_event(NOW + 2)));
    assert_eq!(sink.dropped(), 2);
    let state = state.with_query_log(log);
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let item = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "querylog.dropped")
        .expect("querylog.dropped");
    assert!(item["params"]["count"].as_u64().unwrap() >= 2);
    assert_eq!(item["target_route"], "/query-log");
}

#[tokio::test]
async fn a_failed_backup_run_in_kv_raises_an_alert() {
    let (state, viewer, _, db) = base_state().await;
    db.kv_set(
        "backups.last_run",
        &json!({
            "at": NOW as i64,
            "result": "error",
            "code": "control_api.backups.failed"
        })
        .to_string(),
    )
    .await
    .unwrap();
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let item = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "system.backup.failed")
        .expect("backup failed");
    assert_eq!(item["params"]["code"], "control_api.backups.failed");
    assert_eq!(item["target_route"], "/settings/config");
}

#[tokio::test]
async fn a_cached_update_check_failure_raises_an_alert_when_enabled() {
    let (state, viewer, _, db) = base_state().await;
    let service = ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    );
    service
        .replace(
            json!({
                "filtering": {},
                "clients": {},
                "policy": {},
                "listeners": {},
                "tls": {},
                "control_api_settings": { "update_check": true }
            }),
            &ConfigActor::new("alerts", "test"),
            None,
        )
        .await
        .unwrap();
    // Unreachable loopback URL: warms the update cache with the stable failure
    // code without leaving the machine (same path production uses).
    let state = state
        .with_config_service(Arc::new(service))
        .with_update_api_url("http://127.0.0.1:9/repos/dnscraft/dnscraft/releases/latest");
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let warm = Request::builder()
        .uri("/api/v1/update/check")
        .header(header::AUTHORIZATION, format!("Bearer {viewer}"))
        .body(Body::empty())
        .unwrap();
    let warm_res = router.oneshot(warm).await.unwrap();
    assert_eq!(warm_res.status(), StatusCode::OK);
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        alert_ids(&body).contains(&"system.update.unreachable"),
        "{body}"
    );
}

#[tokio::test]
async fn corrupt_tls_store_is_critical() {
    let (state, viewer, _, _) = base_state().await;
    let mut tls = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
    tls.store = Some(StoreHealth {
        path: "/var/lib/dnscraft/tls".to_owned(),
        writable: false,
        last_write: None,
        corrupt: true,
    });
    let state = state.with_tls(Arc::new(FixedTls(tls)));
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let item = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "tls.store.corrupt")
        .expect("store corrupt");
    assert_eq!(item["severity"], "critical");
}
