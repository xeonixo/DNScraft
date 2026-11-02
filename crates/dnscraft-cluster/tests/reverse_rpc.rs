//! Reverse RPC over the sub-initiated stream (protocol v2).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_cluster::{
    ClusterCa, ClusterClient, ClusterServer, ClusterServerConfig, ClusterStore, ListenConfig,
    LogIngest, NodeIdentity, PendingNodeIdentity, QuotaConfig, RPC_NODE_STATUS, RelayResponse,
    RelayedActor, RpcResponse, StreamRecord, TlsPaths, WriteExecutor,
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
}

async fn start_env() -> TestEnv {
    let _ = rustls::crypto::ring::default_provider().install_default();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-reverse-rpc-{}-{id}",
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
async fn master_invokes_node_status_rpc() {
    let env = start_env().await;
    let identity = enroll_node(&env, "node-a").await;
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let client = ClusterClient::new(&env.url, &identity, Arc::clone(&clock) as _).unwrap();
    let reply_client = ClusterClient::new(&env.url, &identity, clock).unwrap();
    let shutdown = tokio::sync::Notify::new();
    let mut stream = client.connect_with(None, None, &shutdown).await.unwrap();

    let broadcast = env.server.broadcast_handle();
    let invoke = tokio::spawn(async move {
        // Give the stream a moment to register on the master.
        tokio::time::sleep(Duration::from_millis(100)).await;
        broadcast
            .invoke_rpc("node-a", RPC_NODE_STATUS, json!({}), Duration::from_secs(5))
            .await
    });

    let handled = tokio::spawn(async move {
        loop {
            match stream.next_record().await {
                Ok(StreamRecord::RpcRequest(request)) => {
                    assert_eq!(request.method, RPC_NODE_STATUS);
                    let response =
                        RpcResponse::ok(request.request_id, json!({ "role": "sub_node", "ok": true }));
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
    assert_eq!(response.data.unwrap()["ok"], true);

    env.server.shutdown().await;
}
