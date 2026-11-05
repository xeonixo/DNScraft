//! Prefer-QUIC dial with HTTP/2 fallback on the cluster downstream stream.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ActiveTransport, ClusterCa, ClusterClient, ClusterServer, ClusterServerConfig, ClusterStore,
    ListenConfig, LogIngest, NodeIdentity, PendingNodeIdentity, QuotaConfig, RelayResponse,
    RelayedActor, TlsPaths, TransportMode, WriteExecutor,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::Value;

struct NoWrites;

#[async_trait]
impl WriteExecutor for NoWrites {
    async fn execute(
        &self,
        _node_id: &str,
        _request_id: &str,
        _actor: RelayedActor,
        _method: String,
        _path: String,
        _body: Value,
        _if_match: Option<String>,
        _idempotency_key: Option<String>,
    ) -> Result<RelayResponse, dnscraft_cluster::ClusterError> {
        Err(dnscraft_cluster::ClusterError::Internal {
            message: "unused".to_owned(),
        })
    }
}

struct NoLogs;

#[async_trait]
impl LogIngest for NoLogs {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        _last_seq: u64,
        _records: &[dnscraft_cluster::LogRecord],
    ) -> Result<u64, dnscraft_cluster::ClusterError> {
        Ok(0)
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, dnscraft_cluster::ClusterError> {
        Ok(0)
    }
}

struct TestEnv {
    server: ClusterServer,
    store: ClusterStore,
    url: String,
    dir: std::path::PathBuf,
}

async fn start_env() -> TestEnv {
    let _ = rustls::crypto::ring::default_provider().install_default();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-transport-quic-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let ca = ClusterCa::load_or_generate(&dir.join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), Duration::from_secs(900))
        .await
        .unwrap();
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
                share_with_listener: None,
            },
            server_name: "127.0.0.1".to_owned(),
            node_cert_ttl: Duration::from_secs(86400),
            quota: QuotaConfig::default(),
            timing: dnscraft_cluster::TimingConfig::default(),
        },
        ca,
        store.clone(),
        clock,
        Arc::new(NoWrites),
        Arc::new(NoLogs),
        None,
    )
    .await
    .unwrap();
    let url = format!("https://{}", server.addr());
    TestEnv {
        server,
        store,
        url,
        dir,
    }
}

async fn enroll_node(env: &TestEnv, node_id: &str) -> NodeIdentity {
    let token = env.store.mint_join_token(node_id).await.unwrap();
    let pending = PendingNodeIdentity::generate(node_id).unwrap();
    let response = ClusterClient::enroll(
        &env.url,
        env.server.server_cert_pem(),
        pending.request(Secret::new(token.expose())),
    )
    .await
    .unwrap();
    let paths = TlsPaths {
        ca_cert: env.dir.join(format!("{node_id}-ca.pem")),
        node_cert: env.dir.join(format!("{node_id}.pem")),
        node_key: env.dir.join(format!("{node_id}.key")),
    };
    pending.persist(&response, &paths).unwrap()
}

#[tokio::test]
async fn auto_mode_prefers_quic_or_falls_back_to_h2() {
    let env = start_env().await;
    let identity = enroll_node(&env, "auto-node").await;
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let client = ClusterClient::new(&env.url, &identity, clock)
        .unwrap()
        .with_transport_mode(TransportMode::Auto)
        .with_quic_connect_timeout(Duration::from_secs(2));

    let shutdown = tokio::sync::Notify::new();
    let stream = client.connect_with(None, None, &shutdown).await.unwrap();
    let transport = stream.transport();
    assert!(
        transport == ActiveTransport::Quic || transport == ActiveTransport::H2,
        "expected quic or h2, got {transport}"
    );
    assert_eq!(client.active_transport(), transport);
    if transport == ActiveTransport::H2 {
        assert_eq!(
            client.fallback_reason(),
            Some(dnscraft_cluster::FallbackReason::QuicUnavailable)
        );
    }
    env.server.shutdown().await;
}

#[tokio::test]
async fn h2_only_skips_quic() {
    let env = start_env().await;
    let identity = enroll_node(&env, "h2-node").await;
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let client = ClusterClient::new(&env.url, &identity, clock)
        .unwrap()
        .with_transport_mode(TransportMode::H2Only);

    let shutdown = tokio::sync::Notify::new();
    let stream = client.connect_with(None, None, &shutdown).await.unwrap();
    assert_eq!(stream.transport(), ActiveTransport::H2);
    assert_eq!(client.active_transport(), ActiveTransport::H2);
    assert_eq!(
        client.fallback_reason(),
        Some(dnscraft_cluster::FallbackReason::ModeH2Only)
    );
    env.server.shutdown().await;
}
