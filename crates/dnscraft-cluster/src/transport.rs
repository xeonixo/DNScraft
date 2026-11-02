//! Cluster transport selection: Prefer QUIC (HTTP/3), fall back to HTTP/2.
//!
//! Matches the Cloudflare Tunnel `auto` dial policy: try QUIC with a short
//! budget, then TCP/HTTP/2. See ADR-0008.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default QUIC connect budget before falling back to HTTP/2.
pub const DEFAULT_QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How the node selects its cluster transport.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Prefer QUIC/HTTP/3; fall back to HTTP/2 (default).
    #[default]
    Auto,
    /// Prefer QUIC; still falls back if the peer cannot speak it.
    PreferQuic,
    /// Force HTTP/2 only (no UDP attempt).
    H2Only,
}

impl TransportMode {
    /// Parses a settings/API string (`auto`, `prefer_quic`, `h2_only`).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "prefer_quic" => Some(Self::PreferQuic),
            "h2_only" => Some(Self::H2Only),
            _ => None,
        }
    }

    /// Wire / settings string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PreferQuic => "prefer_quic",
            Self::H2Only => "h2_only",
        }
    }

    /// Whether the dialer should attempt QUIC first.
    pub fn try_quic(self) -> bool {
        !matches!(self, Self::H2Only)
    }
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The transport actually carrying a live cluster session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveTransport {
    /// QUIC / HTTP/3.
    Quic,
    /// TCP / HTTP/2.
    H2,
    /// No live session.
    None,
}

impl ActiveTransport {
    /// Wire / status string (`quic`, `h2`, `none`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::H2 => "h2",
            Self::None => "none",
        }
    }
}

impl fmt::Display for ActiveTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the session is on HTTP/2 after Prefer-QUIC failed (status / settings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// Outbound UDP / QUIC handshake timed out or was blocked.
    QuicUnavailable,
    /// Peer only speaks protocol 1 (HTTP/2).
    PeerProtocol1,
    /// Operator forced `h2_only`.
    ModeH2Only,
    /// QUIC connected but ALPN/HTTP/3 negotiation failed.
    H3NegotiateFailed,
}

impl FallbackReason {
    /// Stable machine code for status/API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::QuicUnavailable => "quic_unavailable",
            Self::PeerProtocol1 => "peer_protocol_1",
            Self::ModeH2Only => "mode_h2_only",
            Self::H3NegotiateFailed => "h3_negotiate_failed",
        }
    }
}

/// Live view of which transport is in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportStatus {
    /// Configured dial / listen preference.
    pub mode: TransportMode,
    /// Transport of the current session (or `none`).
    pub active: ActiveTransport,
    /// Present when Prefer-QUIC fell back to HTTP/2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<FallbackReason>,
    /// Negotiated protocol version on the live session, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
}

impl Default for TransportStatus {
    fn default() -> Self {
        Self {
            mode: TransportMode::Auto,
            active: ActiveTransport::None,
            fallback_reason: None,
            protocol_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_round_trip() {
        for mode in [
            TransportMode::Auto,
            TransportMode::PreferQuic,
            TransportMode::H2Only,
        ] {
            assert_eq!(TransportMode::parse(mode.as_str()), Some(mode));
        }
        assert!(TransportMode::parse("bogus").is_none());
        assert!(TransportMode::Auto.try_quic());
        assert!(!TransportMode::H2Only.try_quic());
    }
}
