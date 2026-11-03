//! Optional cluster control-plane attachment on a shared DoH `:443` listener.
//!
//! When set, DoH TLS selects the cluster server certificate for the configured
//! cluster SNI and routes `/cluster/v1/*` to the attached handler. Other SNIs
//! keep the ACME DoH certificate and `/dns-query` / web paths.

use bytes::Bytes;
use http::Request;
use rustls::RootCertStore;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};

use crate::web::WebFuture;

/// Whether a ClientHello should select the cluster certificate.
///
/// rustls exposes only **DNS** SNIs via [`ClientHello::server_name`]; an IP SNI
/// (typical for `master_url = https://172.x.x.x`) becomes `None`. When the
/// configured cluster SNI is itself an IP, treat a missing SNI as cluster.
pub fn cluster_sni_selected(cluster_sni: &str, client_sni: Option<&str>) -> bool {
    match client_sni {
        Some(name) => name.eq_ignore_ascii_case(cluster_sni),
        None => cluster_sni.parse::<IpAddr>().is_ok(),
    }
}

/// Future returned by a [`ClusterHandler`].
pub type ClusterFuture = WebFuture;

/// Serves one `/cluster/v1/*` request with the TCP peer and optional client certificate DER.
///
/// The request body is already buffered (`Bytes`) so TCP (Incoming) and HTTP/3
/// share the same handler.
pub type ClusterHandler = Arc<
    dyn Fn(SocketAddr, Option<Vec<u8>>, Request<Bytes>) -> ClusterFuture + Send + Sync,
>;

/// Material needed to mux cluster mTLS onto a DoH listener.
#[derive(Clone)]
pub struct ClusterAttachment {
    /// SNI that selects the cluster server certificate (often the listen IP).
    pub cluster_sni: String,
    /// Cluster CA PEM (client cert verifier).
    pub ca_cert_pem: String,
    /// Cluster server certificate PEM.
    pub server_cert_pem: String,
    /// Cluster server private key PEM.
    pub server_key_pem: String,
    /// HTTP handler for `/cluster/v1/*`.
    pub handler: ClusterHandler,
}

impl ClusterAttachment {
    /// Whether `path` is a cluster control-plane path.
    pub fn is_cluster_path(path: &str) -> bool {
        path == "/cluster/v1" || path.starts_with("/cluster/v1/")
    }

    /// Whether `sni` selects this attachment (see [`cluster_sni_selected`]).
    pub fn matches_sni(&self, sni: Option<&str>) -> bool {
        cluster_sni_selected(&self.cluster_sni, sni)
    }
}

/// Late-bound cluster attachment shared by DoH listeners of a [`crate::ListenerSet`].
#[derive(Default)]
pub struct ClusterSlot {
    attachment: OnceLock<ClusterAttachment>,
}

impl ClusterSlot {
    /// Installs the attachment; returns `false` when one is already installed.
    pub fn set(&self, attachment: ClusterAttachment) -> bool {
        self.attachment.set(attachment).is_ok()
    }

    /// Attached cluster control plane, if any.
    pub fn get(&self) -> Option<&ClusterAttachment> {
        self.attachment.get()
    }
}

/// [`ResolvesServerCert`] that serves the cluster cert for the cluster SNI and
/// otherwise delegates to the DoH/ACME resolver.
pub struct MuxCertResolver {
    doh: Arc<dyn ResolvesServerCert>,
    cluster_sni: String,
    cluster_key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for MuxCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxCertResolver")
            .field("cluster_sni", &self.cluster_sni)
            .finish_non_exhaustive()
    }
}

impl MuxCertResolver {
    /// Builds a mux resolver from an already-parsed cluster key.
    pub fn new(
        doh: Arc<dyn ResolvesServerCert>,
        cluster_sni: String,
        cluster_key: Arc<CertifiedKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            doh,
            cluster_sni,
            cluster_key,
        })
    }

    /// Parses PEMs into a [`CertifiedKey`].
    pub fn certified_key_from_pem(
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Arc<CertifiedKey>, String> {
        let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cluster cert PEM: {error}"))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|error| format!("cluster key PEM: {error}"))?;
        let provider = rustls::crypto::ring::default_provider();
        CertifiedKey::from_der(certs, key, &provider)
            .map(Arc::new)
            .map_err(|error| format!("cluster CertifiedKey: {error}"))
    }
}

impl ResolvesServerCert for MuxCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if cluster_sni_selected(&self.cluster_sni, client_hello.server_name()) {
            return Some(Arc::clone(&self.cluster_key));
        }
        self.doh.resolve(client_hello)
    }
}

/// Builds a rustls server config that accepts missing client certs and validates
/// presented certs against the cluster CA (enroll + mTLS on one socket).
pub fn colocated_tcp_server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    ca_cert_pem: &str,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
        .map_err(|error| format!("cluster CA PEM: {error}"))?;
    roots
        .add(ca)
        .map_err(|error| format!("cluster CA root: {error}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|error| format!("cluster client verifier: {error}"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| format!("TLS versions: {error}"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// Same as [`colocated_tcp_server_config`] but ALPN `h3` only and 0-RTT off.
pub fn colocated_quic_server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    ca_cert_pem: &str,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
        .map_err(|error| format!("cluster CA PEM: {error}"))?;
    roots
        .add(ca)
        .map_err(|error| format!("cluster CA root: {error}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|error| format!("cluster client verifier: {error}"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("TLS 1.3: {error}"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// Shared SNI seen during the last resolve (best-effort, per-connection resolver).
#[derive(Default)]
pub struct ObservedSni {
    inner: RwLock<Option<String>>,
}

impl ObservedSni {
    /// Records the ClientHello server name.
    pub fn set(&self, sni: Option<&str>) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = sni.map(str::to_owned);
    }

    /// Returns the recorded SNI.
    pub fn get(&self) -> Option<String> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Wraps a resolver and records the ClientHello SNI.
pub struct ObservingCertResolver {
    inner: Arc<dyn ResolvesServerCert>,
    observed: Arc<ObservedSni>,
}

impl std::fmt::Debug for ObservingCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservingCertResolver").finish_non_exhaustive()
    }
}

impl ObservingCertResolver {
    /// New observing wrapper.
    pub fn new(inner: Arc<dyn ResolvesServerCert>, observed: Arc<ObservedSni>) -> Arc<Self> {
        Arc::new(Self { inner, observed })
    }
}

impl ResolvesServerCert for ObservingCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.observed.set(client_hello.server_name());
        self.inner.resolve(client_hello)
    }
}

#[cfg(test)]
mod tests {
    use super::cluster_sni_selected;

    #[test]
    fn dns_sni_matches_case_insensitively() {
        assert!(cluster_sni_selected("ns1.dns.example", Some("NS1.dns.example")));
        assert!(!cluster_sni_selected("ns1.dns.example", Some("other.example")));
        assert!(!cluster_sni_selected("ns1.dns.example", None));
    }

    #[test]
    fn missing_sni_selects_cluster_when_sni_is_ip() {
        assert!(cluster_sni_selected("172.20.10.20", None));
        assert!(cluster_sni_selected("172.20.10.20", Some("172.20.10.20")));
        assert!(!cluster_sni_selected("172.20.10.20", Some("dns.example")));
    }
}
