//! Cluster + DoH SNI/path colocation on one TCP listener.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use dnscraft_listeners::{
    ClusterAttachment, ClusterSlot, DohServeParams, DohStats, EmptyClientIds, Exposure, FakeHandler,
    Limits, ListenerConfig, Protocol, PublicConfig, SniGate, SystemClock, TlsStats, serve_doh,
};
use dnscraft_policy::ListenerId;
use dnscraft_tls::{CertResolver, ReservedLabels};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use support::certs::{example_dns_cert, self_signed};
use support::{encode_a_query, fake_a_answer};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use tokio_rustls::TlsConnector;

fn install_ring() {
    let _ = default_provider().install_default();
}

#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn connector(alpn: &[&[u8]]) -> TlsConnector {
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(cfg))
}

#[tokio::test]
async fn cluster_path_and_doh_share_one_tcp_port() {
    install_ring();
    let (chain, key, _) = example_dns_cert();
    let certs = Arc::new(CertResolver::new());
    certs.install(&chain, &key).unwrap();

    let (cluster_chain, cluster_key, _) = self_signed(&["127.0.0.1", "localhost"]);
    let cluster_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&cluster_hits);
    let slot = Arc::new(ClusterSlot::default());
    assert!(slot.set(ClusterAttachment {
        cluster_sni: "127.0.0.1".to_owned(),
        ca_cert_pem: String::from_utf8(cluster_chain.clone()).unwrap(),
        server_cert_pem: String::from_utf8(cluster_chain).unwrap(),
        server_key_pem: String::from_utf8(cluster_key).unwrap(),
        handler: Arc::new(move |_peer, _cert, req| {
            hits.fetch_add(1, Ordering::SeqCst);
            let path = req.uri().path().to_owned();
            Box::pin(async move {
                http::Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(
                        Full::new(Bytes::from(format!("cluster:{path}")))
                            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> {
                                match never {}
                            })
                            .boxed_unsync(),
                    )
                    .unwrap()
            })
        }),
    }));

    let (bound_tx, bound_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let stats = Arc::new(DohStats::default());
    let join = tokio::spawn(serve_doh(DohServeParams {
        listener: ListenerConfig {
            node_id: None,
            nodes: Vec::new(),
            id: ListenerId::new("coloc-doh").unwrap(),
            protocol: Protocol::Doh,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            exposure: Exposure::Local,
            h3: false,
            tls_policy: None,
        },
        limits: Limits::default(),
        admission: support::admission_for(&Limits::default(), &PublicConfig::default()),
        handler: Arc::new(FakeHandler::new(fake_a_answer(Ipv4Addr::new(192, 0, 2, 9)))),
        clock: Arc::new(SystemClock),
        stats: Arc::clone(&stats),
        tls_stats: Arc::new(TlsStats::default()),
        certs,
        sni_gate: Arc::new(SniGate {
            public_domain: "example.com".into(),
            reserved: Arc::new(std::sync::RwLock::new(ReservedLabels::new(
                ["node1".into()],
            ))),
            registry: Arc::new(EmptyClientIds),
        }),
        event_sink: None,
        alt_svc_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
        web: Arc::default(),
        cluster: Arc::clone(&slot),
        trusted_proxies: Arc::new(std::sync::RwLock::new(Vec::new())),
        bound: bound_tx,
        shutdown: shutdown_rx,
    }));
    let addr = tokio::time::timeout(Duration::from_secs(2), bound_rx)
        .await
        .unwrap()
        .unwrap();

    // Cluster path on shared socket.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server = ServerName::try_from("127.0.0.1").unwrap();
    let tls = connector(&[b"h2", b"http/1.1"])
        .connect(server, tcp)
        .await
        .unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::GET)
        .uri("/cluster/v1/ping")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"cluster:/cluster/v1/ping");
    assert_eq!(cluster_hits.load(Ordering::SeqCst), 1);

    // DoH query on the same port (ACME / DoH SNI).
    let wire = encode_a_query(1, "example.com");
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server = ServerName::try_from("dns.example.com").unwrap();
    let tls = connector(&[b"h2", b"http/1.1"])
        .connect(server, tcp)
        .await
        .unwrap();
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &wire);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/dns-query?dns={b64}"))
        .header(http::header::ACCEPT, "application/dns-message")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "DoH on colocated socket");

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}
