//! Reverse control RPCs over the sub-initiated cluster session.
//!
//! The master never dials a sub-node. Typed requests travel downstream as
//! [`StreamRecord::RpcRequest`]; the sub replies via `POST /cluster/v1/rpc-reply`
//! (HTTP/2) or an equivalent QUIC response stream. Optional HTTP CONNECT is
//! limited to loopback control-api paths (allowlist).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot;

use crate::error::ClusterError;

/// Hello capability: peer accepts reverse RPC requests.
pub const CAP_REVERSE_RPC: &str = "reverse_rpc";
/// Hello capability: peer accepts allowlisted loopback CONNECT proxying.
pub const CAP_REVERSE_CONNECT: &str = "reverse_connect";

/// Reverse RPC: fetch live node status.
pub const RPC_NODE_STATUS: &str = "node.status";
/// Reverse RPC: fetch a redacted diagnostics bundle.
pub const RPC_NODE_DIAGNOSTICS: &str = "node.diagnostics";
/// Reverse RPC: re-apply the last config snapshot and ack.
pub const RPC_CONFIG_REAPPLY: &str = "config.reapply";
/// Reverse RPC: run a runtime command with acknowledgement.
pub const RPC_RUNTIME_EXEC: &str = "runtime.exec";

/// Default allowlisted methods.
pub const DEFAULT_RPC_METHODS: &[&str] = &[
    RPC_NODE_STATUS,
    RPC_NODE_DIAGNOSTICS,
    RPC_CONFIG_REAPPLY,
    RPC_RUNTIME_EXEC,
];

/// Master → sub reverse RPC (`rpc_request` stream record).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Correlation id (UUID or opaque string); echoed in the response.
    pub request_id: String,
    /// Method name (see `RPC_*` constants).
    pub method: String,
    /// Method-specific parameters.
    #[serde(default)]
    pub params: Value,
    /// Soft deadline for the sub-node, milliseconds from receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Sub → master reverse RPC reply body (`POST /cluster/v1/rpc-reply`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Echo of [`RpcRequest::request_id`].
    pub request_id: String,
    /// Success payload when `error` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Failure when the call did not succeed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorBody>,
}

/// Stable error payload inside [`RpcResponse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorBody {
    /// `cluster.rpc.*` code.
    pub code: String,
    /// Optional structured parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RpcResponse {
    /// Successful reply.
    pub fn ok(request_id: impl Into<String>, data: Value) -> Self {
        Self {
            request_id: request_id.into(),
            data: Some(data),
            error: None,
        }
    }

    /// Failed reply.
    pub fn err(request_id: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            data: None,
            error: Some(RpcErrorBody {
                code: code.into(),
                params: None,
            }),
        }
    }
}

/// Allowlist check for a reverse RPC method.
pub fn method_allowed(method: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|m| m == method)
}

/// Validates that `method` is a known built-in name.
pub fn known_method(method: &str) -> bool {
    DEFAULT_RPC_METHODS.contains(&method)
}

/// Rejects unknown or disallowed methods with a stable error.
pub fn ensure_method(method: &str, allowlist: &[String]) -> Result<(), ClusterError> {
    if !known_method(method) {
        return Err(ClusterError::RpcUnsupported {
            method: method.to_owned(),
        });
    }
    if !method_allowed(method, allowlist) {
        return Err(ClusterError::RpcDenied {
            method: method.to_owned(),
        });
    }
    Ok(())
}

/// Returns true when capabilities include reverse RPC.
pub fn wants_reverse_rpc(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_REVERSE_RPC)
}

/// Returns true when capabilities include reverse CONNECT.
pub fn wants_reverse_connect(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_REVERSE_CONNECT)
}

/// Default path prefixes allowed for loopback CONNECT proxy (read-only GETs).
pub const DEFAULT_CONNECT_PATH_PREFIXES: &[&str] = &["/api/v1/status", "/api/v1/readyz", "/readyz"];

/// Returns true when `path` is under an allowlisted prefix (GET-only policy).
pub fn connect_path_allowed(path: &str, prefixes: &[String]) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    prefixes
        .iter()
        .any(|prefix| path == prefix.as_str() || path.starts_with(&format!("{prefix}/")))
}

/// Returns true when `authority` (host or `host:port`) resolves to loopback.
///
/// Non-loopback LAN/public targets are always denied — CONNECT is only a
/// loopback control-api proxy.
pub fn connect_host_is_loopback(authority: &str) -> bool {
    let authority = authority.trim();
    if authority.is_empty() {
        return false;
    }
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && port.parse::<u16>().is_ok()
        && !host.contains(':')
    {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return ip.is_loopback();
        }
        return host.eq_ignore_ascii_case("localhost");
    }
    if authority.starts_with('[')
        && let Some(end) = authority.find(']')
    {
        let host = &authority[1..end];
        if let Ok(ip) = host.parse::<IpAddr>() {
            return ip.is_loopback();
        }
    }
    authority.eq_ignore_ascii_case("localhost")
}

/// Validates a reverse CONNECT target: must be enabled, loopback-only, and
/// path-allowlisted. Failures use [`ClusterError::ConnectDenied`]
/// (`cluster.reverse_rpc.denied`).
pub fn ensure_connect_request(
    enabled: bool,
    authority: &str,
    path: &str,
    path_prefixes: &[String],
) -> Result<(), ClusterError> {
    if !enabled {
        return Err(ClusterError::ConnectDenied {
            reason: "reverse connect is disabled".to_owned(),
        });
    }
    if !connect_host_is_loopback(authority) {
        return Err(ClusterError::ConnectDenied {
            reason: format!("non-loopback connect target {authority}"),
        });
    }
    if !connect_path_allowed(path, path_prefixes) {
        return Err(ClusterError::ConnectDenied {
            reason: format!("connect path {path} is not allowlisted"),
        });
    }
    Ok(())
}

/// In-flight reverse RPC waiters on the master.
#[derive(Default)]
pub struct RpcPending {
    waiters: Mutex<HashMap<String, oneshot::Sender<RpcResponse>>>,
}

impl RpcPending {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a waiter for `request_id`.
    pub fn register(&self, request_id: String) -> oneshot::Receiver<RpcResponse> {
        let (tx, rx) = oneshot::channel();
        self.waiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(request_id, tx);
        rx
    }

    /// Completes a waiter with `response` (from `/cluster/v1/rpc-reply`).
    pub fn complete(&self, response: RpcResponse) -> bool {
        let Some(tx) = self
            .waiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&response.request_id)
        else {
            return false;
        };
        tx.send(response).is_ok()
    }

    /// Drops a waiter without completing it.
    pub fn cancel(&self, request_id: &str) {
        self.waiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(request_id);
    }
}

/// Waits for an RPC reply with a timeout.
pub async fn wait_rpc(
    pending: &RpcPending,
    request_id: &str,
    rx: oneshot::Receiver<RpcResponse>,
    timeout: Duration,
) -> Result<RpcResponse, ClusterError> {
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => {
            pending.cancel(request_id);
            Err(ClusterError::RpcUnavailable {
                reason: "rpc waiter dropped".to_owned(),
            })
        }
        Err(_) => {
            pending.cancel(request_id);
            Err(ClusterError::RpcTimeout)
        }
    }
}

/// Shared handle used by the master control-api and the cluster server.
pub type SharedRpcPending = Arc<RpcPending>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn method_gate() {
        let allow: Vec<String> = DEFAULT_RPC_METHODS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert!(ensure_method(RPC_NODE_STATUS, &allow).is_ok());
        assert_eq!(
            ensure_method("shell.exec", &allow).unwrap_err().code(),
            "cluster.rpc.unsupported"
        );
        assert_eq!(
            ensure_method(RPC_NODE_STATUS, &[]).unwrap_err().code(),
            "cluster.rpc.denied"
        );
    }

    #[test]
    fn connect_paths() {
        let prefixes: Vec<String> = DEFAULT_CONNECT_PATH_PREFIXES
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert!(connect_path_allowed("/api/v1/status", &prefixes));
        assert!(connect_path_allowed("/api/v1/status?x=1", &prefixes));
        assert!(!connect_path_allowed("/api/v1/config", &prefixes));
    }

    #[test]
    fn connect_host_loopback_only() {
        assert!(connect_host_is_loopback("127.0.0.1"));
        assert!(connect_host_is_loopback("127.0.0.1:8080"));
        assert!(connect_host_is_loopback("::1"));
        assert!(connect_host_is_loopback("[::1]:443"));
        assert!(connect_host_is_loopback("localhost"));
        assert!(connect_host_is_loopback("LOCALHOST:80"));
        assert!(!connect_host_is_loopback("192.0.2.10"));
        assert!(!connect_host_is_loopback("192.0.2.10:443"));
        assert!(!connect_host_is_loopback("example.com"));
        assert!(!connect_host_is_loopback(""));
    }

    #[test]
    fn ensure_connect_gates() {
        let prefixes: Vec<String> = DEFAULT_CONNECT_PATH_PREFIXES
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert!(ensure_connect_request(true, "127.0.0.1:80", "/api/v1/status", &prefixes).is_ok());
        assert_eq!(
            ensure_connect_request(false, "127.0.0.1", "/api/v1/status", &prefixes)
                .unwrap_err()
                .code(),
            "cluster.reverse_rpc.denied"
        );
        assert_eq!(
            ensure_connect_request(true, "192.0.2.10", "/api/v1/status", &prefixes)
                .unwrap_err()
                .code(),
            "cluster.reverse_rpc.denied"
        );
        assert_eq!(
            ensure_connect_request(true, "127.0.0.1", "/api/v1/config", &prefixes)
                .unwrap_err()
                .code(),
            "cluster.reverse_rpc.denied"
        );
    }
}
