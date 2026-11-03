//! Cluster identity and transport for DNScraft.
//!
//! A DNScraft cluster is one `master` plus zero or more `sub_node`s, connected
//! hub-and-spoke with mutual TLS under a dedicated cluster CA. Protocol v2
//! prefers QUIC/HTTP/3 with HTTP/2 fallback, optional zstd compression, and a
//! reverse control channel over the sub-initiated session (ADR-0008).

#![deny(missing_docs)]

mod ca;
mod client;
mod compress;
mod config;
mod enroll;
mod error;
mod identity;
mod log;
mod offline;
mod quota;
mod quic;
mod relay;
mod rpc;
mod server;
mod settings;
mod store;
mod sync;
mod transport;

pub use ca::{ClusterCa, cert_fingerprint};
pub use client::{ClusterClient, ClusterStream};
pub use compress::{
    CAP_COMPRESS_ZSTD, DEFAULT_LEVEL as ZSTD_DEFAULT_LEVEL, ZstdEnvelope, wants_zstd,
};
pub use config::{
    BootstrapCompression, BootstrapReverseRpc, BootstrapTransport, ClusterConfig, JoinConfig,
    ListenConfig, LogConfig, OfflineWritesConfig, QuotaConfig, Role, TimingConfig, TlsPaths,
};
pub use enroll::{
    EnrollRequest, EnrollResponse, PROTOCOL_VERSION, PROTOCOL_VERSION_MIN, RenewRequest, enroll,
    protocol_supported,
};
pub use error::ClusterError;
pub use identity::{NodeIdentity, PendingNodeIdentity};
pub use log::{
    Backfill, FlushOutcome, LogAck, LogBatch, LogIngest, LogOutbox, LogRecord, LogStreamer,
};
pub use offline::{
    ActorValidator, EnqueueOutcome, OfflineQueueStatus, OfflineWriteEntry, OfflineWriteQueue,
    OfflineWriteState, QueuedWrite, ReplayOutcome,
};
pub use relay::{
    RelayResponse, RelayedActor, RuntimeCommand, RuntimeCommandApplier, WriteExecutor, WriteRelay,
};
pub use rpc::{
    CAP_REVERSE_CONNECT, CAP_REVERSE_RPC, DEFAULT_CONNECT_PATH_PREFIXES, DEFAULT_RPC_METHODS,
    RPC_CONFIG_REAPPLY, RPC_NODE_DIAGNOSTICS, RPC_NODE_STATUS, RPC_RUNTIME_EXEC, RpcErrorBody,
    RpcPending, RpcRequest, RpcResponse, SharedRpcPending, connect_host_is_loopback,
    connect_path_allowed, ensure_connect_request, ensure_method, method_allowed, wait_rpc,
    wants_reverse_connect, wants_reverse_rpc,
};
pub use server::{
    AuthSnapshotSource, CloudflareTokenSource, ClusterBroadcast, ClusterColocation, ClusterServer,
    ClusterServerConfig, HeartbeatRequest, HeartbeatResponse, StatusWarning, TlsCertificateSource,
    TlsCsrRequest, TlsCsrResponse, TlsCsrSigner,
};
pub use settings::{
    ClusterSettings, ClusterSettingsUpdate, CompressionSettings, CompressionSettingsUpdate,
    ListenOverride, ReverseRpcSettings, ReverseRpcSettingsUpdate, TransportSettings,
    TransportSettingsUpdate,
};
pub use store::{ClusterNode, ClusterStore, MintedJoinToken};
pub use sync::{
    AuthSnapshotApplier, AuthSnapshotPush, CAP_CLOUDFLARE_TOKEN, CAP_TLS_CERTIFICATE,
    CertInstaller, ClientsDirectoryPush, CloudflareTokenPush, ConfigAck, ConfigApplier, ConfigPush,
    ConfigSync, Hello, NodeLag, SecretPush, StreamError, StreamRecord, TlsCertificatePush,
    TlsRenewed, canonical_snapshot_bytes, snapshot_digest,
};
pub use transport::{
    ActiveTransport, DEFAULT_QUIC_CONNECT_TIMEOUT, FallbackReason, TransportMode, TransportStatus,
};

/// Lowercase hex SHA-256 of `bytes` (used for fingerprints and token hashes).
pub(crate) use dnscraft_common::hash::sha256_hex;

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
