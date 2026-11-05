//! zstd envelopes for large cluster payloads (config snapshots, log batches).
//!
//! Capability: [`CAP_COMPRESS_ZSTD`]. Window ≤ 8 MiB (RFC 9659); both compressed
//! and decompressed sizes are capped (OTel CVE-2024-36129 lesson).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ClusterError;

/// Hello capability: peer accepts zstd envelopes.
pub const CAP_COMPRESS_ZSTD: &str = "compress=zstd";

/// Maximum zstd window size in bytes (RFC 9659 HTTP interoperability).
#[allow(dead_code)] // documented contract for callers configuring encoders
pub const MAX_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
/// Default maximum compressed payload accepted.
pub const DEFAULT_MAX_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum decompressed payload accepted.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: usize = 32 * 1024 * 1024;
/// Default compression level for live traffic (1–3 recommended).
pub const DEFAULT_LEVEL: i32 = 3;

/// JSON envelope wrapping zstd-compressed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZstdEnvelope {
    /// Always `"zstd"`.
    pub encoding: String,
    /// Lowercase hex SHA-256 of the **plaintext** bytes.
    pub sha256: String,
    /// Base64 of the compressed frame.
    pub bytes: String,
}

impl ZstdEnvelope {
    /// Compresses `plain` at `level` into an envelope.
    pub fn compress(plain: &[u8], level: i32) -> Result<Self, ClusterError> {
        let level = level.clamp(1, 3);
        let compressed =
            zstd::bulk::compress(plain, level).map_err(|error| ClusterError::Internal {
                message: format!("zstd compress: {error}"),
            })?;
        if compressed.len() > DEFAULT_MAX_COMPRESSED_BYTES {
            return Err(ClusterError::Compression {
                reason: "compressed payload exceeds limit".to_owned(),
            });
        }
        Ok(Self {
            encoding: "zstd".to_owned(),
            sha256: crate::sha256_hex(plain),
            bytes: B64.encode(compressed),
        })
    }

    /// Decompresses and verifies the digest; enforces size caps.
    pub fn decompress(&self) -> Result<Vec<u8>, ClusterError> {
        self.decompress_with_limits(DEFAULT_MAX_COMPRESSED_BYTES, DEFAULT_MAX_DECOMPRESSED_BYTES)
    }

    /// Decompress with explicit caps (tests / settings).
    pub fn decompress_with_limits(
        &self,
        max_compressed: usize,
        max_decompressed: usize,
    ) -> Result<Vec<u8>, ClusterError> {
        if self.encoding != "zstd" {
            return Err(ClusterError::Compression {
                reason: format!("unsupported encoding {}", self.encoding),
            });
        }
        let compressed =
            B64.decode(self.bytes.as_bytes())
                .map_err(|error| ClusterError::Compression {
                    reason: format!("invalid base64: {error}"),
                })?;
        if compressed.len() > max_compressed {
            return Err(ClusterError::Compression {
                reason: "compressed payload exceeds limit".to_owned(),
            });
        }
        let plain = zstd::bulk::decompress(&compressed, max_decompressed).map_err(|error| {
            ClusterError::Compression {
                reason: format!("zstd decompress: {error}"),
            }
        })?;
        if plain.len() > max_decompressed {
            return Err(ClusterError::Compression {
                reason: "decompressed payload exceeds limit".to_owned(),
            });
        }
        let digest = crate::sha256_hex(&plain);
        if digest != self.sha256 {
            return Err(ClusterError::Compression {
                reason: "plaintext digest mismatch".to_owned(),
            });
        }
        Ok(plain)
    }

    /// Serializes as a JSON value (for nesting inside stream records).
    pub fn to_value(&self) -> Result<Value, ClusterError> {
        serde_json::to_value(self).map_err(|error| ClusterError::Internal {
            message: format!("encode zstd envelope: {error}"),
        })
    }

    /// Parses an envelope from a JSON value.
    pub fn from_value(value: &Value) -> Result<Self, ClusterError> {
        serde_json::from_value(value.clone()).map_err(|error| ClusterError::Compression {
            reason: format!("invalid zstd envelope: {error}"),
        })
    }
}

/// Returns true when `capabilities` advertises [`CAP_COMPRESS_ZSTD`].
pub fn wants_zstd(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == CAP_COMPRESS_ZSTD)
}

/// True when `body` is a JSON object with `"encoding":"zstd"` (envelope shape).
pub fn looks_like_zstd_envelope(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("encoding")
                .and_then(|encoding| encoding.as_str())
                .map(|encoding| encoding == "zstd")
        })
        .unwrap_or(false)
}

/// Decompresses a [`ZstdEnvelope`] body, or returns `body` unchanged.
pub fn maybe_decompress_body(body: &[u8]) -> Result<Vec<u8>, ClusterError> {
    if !looks_like_zstd_envelope(body) {
        return Ok(body.to_vec());
    }
    let envelope: ZstdEnvelope =
        serde_json::from_slice(body).map_err(|error| ClusterError::Compression {
            reason: format!("invalid zstd envelope: {error}"),
        })?;
    envelope.decompress()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plain = br#"{"hello":"world","n":42}"#;
        let env = ZstdEnvelope::compress(plain, 3).unwrap();
        assert_eq!(env.encoding, "zstd");
        let out = env.decompress().unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn rejects_digest_mismatch() {
        let mut env = ZstdEnvelope::compress(b"abc", 1).unwrap();
        env.sha256 = "00".repeat(32);
        assert_eq!(env.decompress().unwrap_err().code(), "cluster.compression");
    }

    #[test]
    fn rejects_oversized_decompress_cap() {
        let env = ZstdEnvelope::compress(b"abcdefghij", 1).unwrap();
        let err = env.decompress_with_limits(16 * 1024 * 1024, 4).unwrap_err();
        assert_eq!(err.code(), "cluster.compression");
    }
}
