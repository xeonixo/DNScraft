//! Fault injection: Prefer-QUIC with UDP occupied → HTTP/2 fallback, then
//! reverse RPC still works on the h2 session (protocol v2 parity).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ActiveTransport, ClusterCa, ClusterClient, ClusterServer, ClusterServerConfig, ClusterStore,
    FallbackReason, ListenConfig, LogIngest, NodeIdentity, PendingNodeIdentity, QuotaConfig,
    RPC_NODE_STATUS, RelayResponse, RelayedActor, RpcResponse, StreamRecord, TlsPaths,
    TransportMode, WriteExecutor,
};
use dnscraft_common::clock::ManualClock;
use dnscraft_common::secret::Secret;
use serde_json::{Value, json};

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
    /// Holds the UDP port so the master's QUIC bind fails (TCP-only).
    _udp_block: UdpSocket,
}

async fn start_tcp_only_env() -> TestEnv {
    let _ = rustls::crypto::ring::default_provider().install_default();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-fallback-rpc-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Occupy a UDP port first so ClusterServer's QUIC bind fails and only TCP/h2 remains.
    let udp_block = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = udp_block.local_addr().unwrap().port();

    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let ca = ClusterCa::load_or_generate(&dir.join("ca.pem")).unwrap();
    let store = ClusterStore::open_in_memory(clock.clone(), Duration::from_secs(900))
        .await
        .unwrap();
    let server = ClusterServer::start(
        ClusterServerConfig {
            listen: ListenConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
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
    assert_eq!(server.addr().port(), port);
    let url = format!("https://{}", server.addr());
    TestEnv {
        server,
        store,
        url,
        dir,
        _udp_block: udp_block,
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
async fn udp_blocked_falls_back_to_h2_and_reverse_rpc_works() {
    let env = start_tcp_only_env().await;
    let identity = enroll_node(&env, "fb-node").await;
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let client = ClusterClient::new(&env.url, &identity, Arc::clone(&clock) as _)
        .unwrap()
        .with_transport_mode(TransportMode::Auto)
        .with_quic_connect_timeout(Duration::from_millis(200));
    let reply_client = ClusterClient::new(&env.url, &identity, clock).unwrap();

    let shutdown = tokio::sync::Notify::new();
    let mut stream = client.connect_with(None, None, &shutdown).await.unwrap();
    assert_eq!(stream.transport(), ActiveTransport::H2);
    assert_eq!(client.active_transport(), ActiveTransport::H2);
    assert_eq!(
        client.fallback_reason(),
        Some(FallbackReason::QuicUnavailable)
    );

    // CONNECT gate (unit-level parity used by the reverse tunnel): loopback ok, LAN denied.
    let prefixes: Vec<String> = dnscraft_cluster::DEFAULT_CONNECT_PATH_PREFIXES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    dnscraft_cluster::ensure_connect_request(true, "127.0.0.1:80", "/api/v1/status", &prefixes)
        .unwrap();
    assert_eq!(
        dnscraft_cluster::ensure_connect_request(true, "192.0.2.10", "/api/v1/status", &prefixes)
            .unwrap_err()
            .code(),
        "cluster.reverse_rpc.denied"
    );

    let broadcast = env.server.broadcast_handle();
    let invoke = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        broadcast
            .invoke_rpc("fb-node", RPC_NODE_STATUS, json!({}), Duration::from_secs(5))
            .await
    });

    let handled = tokio::spawn(async move {
        loop {
            match stream.next_record().await {
                Ok(StreamRecord::RpcRequest(request)) => {
                    assert_eq!(request.method, RPC_NODE_STATUS);
                    let response = RpcResponse::ok(
                        request.request_id,
                        json!({ "ok": true, "via": "h2_fallback" }),
                    );
                    reply_client.post_rpc_reply(&response).await.unwrap();
                    break;
                }
                Ok(_) => continue,
                Err(error) => panic!("stream ended: {error}"),
            }
        }
    });

    let response = invoke.await.unwrap().unwrap();
    handled.await.unwrap();
    assert!(response.error.is_none());
    assert_eq!(response.data.unwrap()["via"], "h2_fallback");

    env.server.shutdown().await;
}
