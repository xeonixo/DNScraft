//! Node-local cluster settings (API/UI), not part of the fleet config snapshot.
//!
//! Persisted under the data directory as JSON so the Web UI can change
//! transport, compression and reverse-RPC without rewriting the bootstrap TOML.
//! Listen bind/port changes set [`ClusterSettings::restart_required`].

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::compress::DEFAULT_LEVEL;
use crate::config::{DEFAULT_CLUSTER_PORT, ListenConfig};
use crate::error::ClusterError;
use crate::rpc::{DEFAULT_CONNECT_PATH_PREFIXES, DEFAULT_RPC_METHODS};
use crate::transport::{
    ActiveTransport, DEFAULT_QUIC_CONNECT_TIMEOUT, FallbackReason, TransportMode, TransportStatus,
};

/// On-disk / API shape for cluster settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterSettings {
    /// Transport preference.
    #[serde(default)]
    pub transport: TransportSettings,
    /// Compression preference.
    #[serde(default)]
    pub compression: CompressionSettings,
    /// Reverse RPC preference.
    #[serde(default)]
    pub reverse_rpc: ReverseRpcSettings,
    /// Optional listen override (master); changing it requires restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<ListenOverride>,
    /// Sub-node master URL override (reconnect/restart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_url: Option<String>,
    /// Live transport status (read-only in GET responses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TransportStatus>,
    /// True when listen bind/port was changed and is not yet active.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restart_required: bool,
}

/// `[cluster.transport]` / settings.transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportSettings {
    /// Dial / accept preference.
    #[serde(default)]
    pub mode: TransportMode,
    /// QUIC connect budget before HTTP/2 fallback (seconds as human duration in TOML;
    /// milliseconds in JSON API as `quic_connect_timeout_ms`).
    #[serde(default = "default_quic_timeout_ms")]
    pub quic_connect_timeout_ms: u64,
}

impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            mode: TransportMode::Auto,
            quic_connect_timeout_ms: DEFAULT_QUIC_CONNECT_TIMEOUT.as_millis() as u64,
        }
    }
}

fn default_quic_timeout_ms() -> u64 {
    DEFAULT_QUIC_CONNECT_TIMEOUT.as_millis() as u64
}

/// Compression settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompressionSettings {
    /// Advertise / use zstd when the peer supports it.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// zstd level 1–3.
    #[serde(default = "default_level")]
    pub level: i32,
}

impl Default for CompressionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            level: DEFAULT_LEVEL,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_level() -> i32 {
    DEFAULT_LEVEL
}

/// Reverse RPC / CONNECT settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReverseRpcSettings {
    /// Accept / send typed reverse RPCs.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allowed method names.
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    /// Allow loopback CONNECT proxy.
    #[serde(default)]
    pub connect_enabled: bool,
    /// Allowed path prefixes for CONNECT GETs.
    #[serde(default = "default_connect_paths")]
    pub connect_paths: Vec<String>,
}

impl Default for ReverseRpcSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            methods: default_methods(),
            connect_enabled: false,
            connect_paths: default_connect_paths(),
        }
    }
}

fn default_methods() -> Vec<String> {
    DEFAULT_RPC_METHODS.iter().map(|s| (*s).to_owned()).collect()
}
fn default_connect_paths() -> Vec<String> {
    DEFAULT_CONNECT_PATH_PREFIXES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// Listen override stored in settings (master).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenOverride {
    /// Bind address string (parsed when applied).
    pub bind: String,
    /// Port (default 443).
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    DEFAULT_CLUSTER_PORT
}

impl ClusterSettings {
    /// Path of the node-local settings file under `data_dir`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("cluster").join("settings.json")
    }

    /// Loads settings from disk, or defaults if missing.
    pub fn load(data_dir: &Path) -> Result<Self, ClusterError> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path).map_err(|error| ClusterError::Internal {
            message: format!("read {}: {error}", path.display()),
        })?;
        serde_json::from_str(&text).map_err(|error| ClusterError::Internal {
            message: format!("parse {}: {error}", path.display()),
        })
    }

    /// Atomically writes settings to disk.
    pub fn save(&self, data_dir: &Path) -> Result<(), ClusterError> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| ClusterError::Internal {
                message: format!("mkdir {}: {error}", parent.display()),
            })?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|error| ClusterError::Internal {
            message: format!("encode settings: {error}"),
        })?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, text.as_bytes()).map_err(|error| ClusterError::Internal {
            message: format!("write {}: {error}", tmp.display()),
        })?;
        fs::rename(&tmp, &path).map_err(|error| ClusterError::Internal {
            message: format!("rename {}: {error}", path.display()),
        })?;
        Ok(())
    }

    /// Merges a PUT body into `self`, marking restart when listen changes.
    pub fn apply_update(&mut self, update: ClusterSettingsUpdate) -> Result<(), ClusterError> {
        if let Some(transport) = update.transport {
            if let Some(mode) = transport.mode {
                self.transport.mode =
                    TransportMode::parse(&mode).ok_or_else(|| ClusterError::RoleInvalid {
                        reason: format!("unknown transport.mode {mode}"),
                    })?;
            }
            if let Some(ms) = transport.quic_connect_timeout_ms {
                if ms == 0 || ms > 60_000 {
                    return Err(ClusterError::RoleInvalid {
                        reason: "quic_connect_timeout_ms must be 1..=60000".to_owned(),
                    });
                }
                self.transport.quic_connect_timeout_ms = ms;
            }
        }
        if let Some(compression) = update.compression {
            if let Some(enabled) = compression.enabled {
                self.compression.enabled = enabled;
            }
            if let Some(level) = compression.level {
                if !(1..=3).contains(&level) {
                    return Err(ClusterError::RoleInvalid {
                        reason: "compression.level must be 1..=3".to_owned(),
                    });
                }
                self.compression.level = level;
            }
        }
        if let Some(reverse) = update.reverse_rpc {
            if let Some(enabled) = reverse.enabled {
                self.reverse_rpc.enabled = enabled;
            }
            if let Some(methods) = reverse.methods {
                self.reverse_rpc.methods = methods;
            }
            if let Some(enabled) = reverse.connect_enabled {
                self.reverse_rpc.connect_enabled = enabled;
            }
            if let Some(paths) = reverse.connect_paths {
                self.reverse_rpc.connect_paths = paths;
            }
        }
        if let Some(listen) = update.listen {
            let changed = self.listen.as_ref() != Some(&listen);
            self.listen = Some(listen);
            if changed {
                self.restart_required = true;
            }
        }
        if let Some(url) = update.master_url {
            self.master_url = Some(url);
        }
        Ok(())
    }

    /// Attaches live transport status for GET responses.
    pub fn with_status(
        mut self,
        active: ActiveTransport,
        fallback: Option<FallbackReason>,
        protocol_version: Option<u32>,
    ) -> Self {
        self.status = Some(TransportStatus {
            mode: self.transport.mode,
            active,
            fallback_reason: fallback,
            protocol_version,
        });
        self
    }

    /// Effective listen from settings override or bootstrap.
    pub fn effective_listen(&self, bootstrap: Option<&ListenConfig>) -> Option<ListenOverride> {
        if let Some(listen) = &self.listen {
            return Some(listen.clone());
        }
        bootstrap.map(|l| ListenOverride {
            bind: l.bind.to_string(),
            port: l.port,
        })
    }
}

/// Partial update body for `PUT /api/v1/cluster/settings`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClusterSettingsUpdate {
    /// Optional transport patch.
    #[serde(default)]
    pub transport: Option<TransportSettingsUpdate>,
    /// Optional compression patch.
    #[serde(default)]
    pub compression: Option<CompressionSettingsUpdate>,
    /// Optional reverse RPC patch.
    #[serde(default)]
    pub reverse_rpc: Option<ReverseRpcSettingsUpdate>,
    /// Optional listen override.
    #[serde(default)]
    pub listen: Option<ListenOverride>,
    /// Optional master URL (sub-node).
    #[serde(default)]
    pub master_url: Option<String>,
}

/// Transport fields in a settings PUT.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TransportSettingsUpdate {
    /// `auto` / `prefer_quic` / `h2_only`.
    #[serde(default)]
    pub mode: Option<String>,
    /// QUIC connect timeout in milliseconds.
    #[serde(default)]
    pub quic_connect_timeout_ms: Option<u64>,
}

/// Compression fields in a settings PUT.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CompressionSettingsUpdate {
    /// Enable zstd.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Level 1–3.
    #[serde(default)]
    pub level: Option<i32>,
}

/// Reverse RPC fields in a settings PUT.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ReverseRpcSettingsUpdate {
    /// Enable typed RPCs.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Method allowlist.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Enable CONNECT proxy.
    #[serde(default)]
    pub connect_enabled: Option<bool>,
    /// CONNECT path prefixes.
    #[serde(default)]
    pub connect_paths: Option<Vec<String>>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn round_trip_disk() {
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-cluster-settings-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let mut settings = ClusterSettings::default();
        settings.transport.mode = TransportMode::H2Only;
        settings.save(&dir).unwrap();
        let loaded = ClusterSettings::load(&dir).unwrap();
        assert_eq!(loaded.transport.mode, TransportMode::H2Only);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_update_rejects_bad_level_and_marks_restart() {
        let mut settings = ClusterSettings::default();
        let err = settings
            .apply_update(ClusterSettingsUpdate {
                compression: Some(CompressionSettingsUpdate {
                    enabled: None,
                    level: Some(9),
                }),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(err.code(), "cluster.role.invalid");

        settings
            .apply_update(ClusterSettingsUpdate {
                listen: Some(ListenOverride {
                    bind: "127.0.0.1".to_owned(),
                    port: 8443,
                }),
                ..Default::default()
            })
            .unwrap();
        assert!(settings.restart_required);
        assert_eq!(settings.listen.as_ref().map(|l| l.port), Some(8443));
    }
}
