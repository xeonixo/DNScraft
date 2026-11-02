//! QUIC / HTTP/3 cluster transport (dual-stack with TCP + HTTP/2).
//!
//! The master binds UDP on the same address as the TCP listener when the OS
//! allows it. Protected routes are served by the same axum router as HTTP/2.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, EndpointConfig, Incoming, ServerConfig, TokioRuntime, VarInt};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::CertificateDer as CertDer;
use tokio::sync::{Semaphore, watch};
use tower_service::Service;

use crate::error::ClusterError;
use crate::identity::NodeIdentity;
use crate::server::{
    ClusterRouter, NodeSlot, NodeSlots, PeerIdentity, PeerSocketAddr, HANDSHAKE_TIMEOUT,
};
use crate::sync::StreamRecord;
const ALPN_H3: &[u8] = b"h3";

/// TLS 1.3 + HTTP/3 server: cluster CA client verifier, ALPN `h3`, 0-RTT off.
pub(crate) fn quic_server_tls_config(
    ca_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<rustls::ServerConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .map_err(|error| tls_config_error(format!("cluster CA PEM: {error}")))?;
    roots
        .add(ca)
        .map_err(|error| tls_config_error(format!("cluster CA root: {error}")))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|error| tls_config_error(format!("client certificate verifier: {error}")))?;

    let certs = CertificateDer::pem_slice_iter(server_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tls_config_error(format!("master certificate PEM: {error}")))?;
    let key = PrivateKeyDer::from_pem_slice(server_key_pem.as_bytes())
        .map_err(|error| tls_config_error(format!("master key PEM: {error}")))?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| tls_config_error(format!("TLS 1.3: {error}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| tls_config_error(format!("master certificate/key: {error}")))?;
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

fn tls_config_error(message: String) -> ClusterError {
    ClusterError::TransportTls { message }
}

/// Binds a QUIC endpoint on `addr` (same UDP port as the TCP cluster listener).
pub(crate) async fn bind_quic_endpoint(
    addr: SocketAddr,
    rustls: rustls::ServerConfig,
) -> Result<Endpoint, ClusterError> {
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|error| ClusterError::TransportQuic {
            message: format!("bind cluster QUIC listener {addr}: {error}"),
        })?;
    let std_sock = socket.into_std().map_err(|error| ClusterError::TransportQuic {
        message: format!("cluster QUIC socket into_std: {error}"),
    })?;

    let quic_crypto = QuicServerConfig::try_from(rustls).map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("QuicServerConfig: {error}"),
        }
    })?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(64));
    transport.max_concurrent_uni_streams(VarInt::from_u32(3));
    server_config.transport_config(Arc::new(transport));

    Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(TokioRuntime),
    )
    .map_err(|error| ClusterError::TransportQuic {
        message: format!("cluster QUIC endpoint: {error}"),
    })
}

/// Shared accept-loop inputs for the QUIC listener.
pub(crate) struct QuicAcceptLoop {
    /// Bound QUIC endpoint.
    pub endpoint: Endpoint,
    /// Cluster HTTP routes (same as TCP/HTTP/2).
    pub router: ClusterRouter,
    /// Global connection cap semaphore.
    pub slots: Arc<Semaphore>,
    /// Per-node connection slots.
    pub node_slots: NodeSlots,
    /// Set when the master cluster server shuts down.
    pub shutdown: watch::Receiver<bool>,
}

/// Accepts QUIC connections and serves `/cluster/v1/*` over HTTP/3.
pub(crate) async fn run_quic_accept_loop(params: QuicAcceptLoop) {
    let QuicAcceptLoop {
        endpoint,
        router,
        slots,
        node_slots,
        mut shutdown,
    } = params;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    endpoint.close(VarInt::from_u32(0), b"shutdown");
                    break;
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let permit = match Arc::clone(&slots).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let router = router.clone();
                let node_slots = Arc::clone(&node_slots);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(conn) = accept_quic(incoming).await {
                        serve_quic_connection(conn, router, node_slots).await;
                    }
                });
            }
        }
    }
}

async fn accept_quic(incoming: Incoming) -> Option<quinn::Connection> {
    let connecting = match incoming.accept() {
        Ok(c) => c,
        Err(_) => return None,
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
        Ok(Ok(conn)) => Some(conn),
        _ => None,
    }
}

async fn serve_quic_connection(
    conn: quinn::Connection,
    router: ClusterRouter,
    node_slots: NodeSlots,
) {
    let peer_addr = conn.remote_address();
    let peer = peer_identity_from_conn(&conn);
    let _node_slot = match peer.as_ref().and_then(|peer| peer.node_id.clone()) {
        Some(node_id) => match NodeSlot::acquire(&node_slots, node_id) {
            Some(slot) => Some(slot),
            None => {
                conn.close(VarInt::from_u32(0), b"cap");
                return;
            }
        },
        None => None,
    };

    let mut h3_conn = match h3::server::builder()
        .build(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(c) => c,
        Err(_) => {
            conn.close(VarInt::from_u32(0), b"h3");
            return;
        }
    };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let router = router.clone();
                let peer = peer.clone();
                tokio::spawn(async move {
                    let _ = dispatch_h3_request(resolver, router, peer, peer_addr).await;
                });
            }
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

fn peer_identity_from_conn(conn: &quinn::Connection) -> Option<PeerIdentity> {
    let certs = conn.peer_identity()?.downcast::<Vec<CertDer>>().ok()?;
    certs
        .first()
        .map(|der| PeerIdentity::from_der(der.as_ref()))
}

async fn dispatch_h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    mut router: ClusterRouter,
    peer: Option<PeerIdentity>,
    peer_addr: SocketAddr,
) -> Result<(), ()> {
    let (req, mut stream) = resolver.resolve_request().await.map_err(|_| ())?;
    let (parts, _) = req.into_parts();
    let body = read_h3_body(&mut stream).await?;

    let mut request = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .body(Body::from(body))
        .map_err(|_| ())?;
    for (name, value) in parts.headers {
        if let Some(name) = name {
            request.headers_mut().append(name, value);
        }
    }
    request.extensions_mut().insert(peer);
    request.extensions_mut().insert(PeerSocketAddr(peer_addr));

    let response = router.call(request).await.map_err(|_| ())?;
    send_h3_response(&mut stream, response).await
}

async fn read_h3_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Bytes, ()> {
    let mut body = Vec::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                body.extend_from_slice(chunk.chunk());
                chunk.advance(chunk.remaining());
            }
            Ok(None) => break,
            Err(_) => return Err(()),
        }
    }
    Ok(Bytes::from(body))
}

async fn send_h3_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    response: Response<Body>,
) -> Result<(), ()> {
    let (parts, mut body) = response.into_parts();
    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    let resp = builder.body(()).map_err(|_| ())?;
    stream.send_response(resp).await.map_err(|_| ())?;

    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    stream.send_data(data).await.map_err(|_| ())?;
                }
            }
            Some(Err(_)) => return Err(()),
            None => break,
        }
    }
    stream.finish().await.map_err(|_| ())?;
    Ok(())
}

/// Live HTTP/3 downstream stream (NDJSON) after the master hello.
pub(crate) struct QuicClusterStream {
    /// Master-bound node id from the hello exchange.
    pub node_id: String,
    /// Negotiated cluster protocol version.
    pub protocol: u32,
    /// Log cursor from the master's hello, if any.
    pub master_highest_log_seq: Option<u64>,
    /// Response body reader.
    pub recv: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    /// Leftover bytes after the last NDJSON line.
    pub buffer: Vec<u8>,
    /// Keeps the HTTP/3 client session open until the stream ends.
    pub session: QuicH3Session,
}

/// Owns QUIC + HTTP/3 client state for one long-lived stream.
#[allow(dead_code)]
pub(crate) struct QuicH3Session {
    /// Keeps the QUIC connection alive for the stream lifetime.
    pub conn: quinn::Connection,
    /// Must outlive open request streams on this connection.
    pub send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Polls the HTTP/3 client driver.
    pub driver: tokio::task::JoinHandle<()>,
}

/// Opens `GET /cluster/v1/stream` over HTTP/3 with mTLS and validates the master hello.
pub(crate) async fn try_open_h3_stream(
    master_url: &str,
    identity: &NodeIdentity,
    hello_bytes: Bytes,
    timeout: Duration,
) -> Result<QuicClusterStream, ClusterError> {
    let connect = open_h3_stream_inner(master_url, identity, hello_bytes);
    match tokio::time::timeout(timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(ClusterError::TransportQuic {
            message: "QUIC connect timed out".to_owned(),
        }),
    }
}

async fn open_h3_stream_inner(
    master_url: &str,
    identity: &NodeIdentity,
    hello_bytes: Bytes,
) -> Result<QuicClusterStream, ClusterError> {
    let (addr, server_name, sni) = quic_authority(master_url)?;
    let client_tls = quic_client_tls(identity)?;
    let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))).map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("QUIC client endpoint: {error}"),
        }
    })?;
    let crypto = QuicClientConfig::try_from(client_tls).map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("QuicClientConfig: {error}"),
        }
    })?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));

    let _server_name = server_name;
    let connecting = endpoint.connect(addr, &sni).map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("QUIC connect: {error}"),
        }
    })?;
    let conn = connecting.await.map_err(|error| ClusterError::TransportQuic {
        message: format!("QUIC handshake: {error}"),
    })?;

    let quinn_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) =
        h3::client::new(quinn_conn).await.map_err(|error| {
            ClusterError::TransportQuic {
                message: format!("HTTP/3 client: {error}"),
            }
        })?;
    let driver_handle = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let path = format!("{master_url}/cluster/v1/stream");
    let req = Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(
            crate::server::PROTOCOL_HEADER,
            crate::enroll::PROTOCOL_VERSION.to_string(),
        )
        .header(http::header::CONTENT_TYPE, "application/x-ndjson")
        .body(())
        .map_err(|error| ClusterError::TransportQuic {
            message: format!("HTTP/3 stream request: {error}"),
        })?;

    let mut stream = send_request.send_request(req).await.map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("HTTP/3 send stream: {error}"),
        }
    })?;
    if !hello_bytes.is_empty() {
        stream
            .send_data(hello_bytes)
            .await
            .map_err(|error| ClusterError::TransportQuic {
                message: format!("HTTP/3 hello body: {error}"),
            })?;
    }
    stream.finish().await.map_err(|error| ClusterError::TransportQuic {
        message: format!("HTTP/3 finish request: {error}"),
    })?;

    let response = stream.recv_response().await.map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("HTTP/3 response: {error}"),
        }
    })?;
    if response.status() != StatusCode::OK {
        return Err(ClusterError::TransportQuic {
            message: format!("HTTP/3 stream status {}", response.status()),
        });
    }

    let node_id = node_id_from_pem(identity.node_cert_pem())?;
    let mut buffer = Vec::new();
    let line = read_line_h3(&mut stream, &mut buffer).await?;
    let record: StreamRecord =
        serde_json::from_slice(&line).map_err(|error| ClusterError::TransportQuic {
            message: format!("invalid stream hello: {error}"),
        })?;
    match record {
        StreamRecord::Hello(hello) => {
            if !crate::enroll::protocol_supported(hello.protocol) {
                return Err(ClusterError::ProtocolVersion);
            }
            if hello.node_id != node_id {
                return Err(ClusterError::TransportQuic {
                    message: "master bound the stream to another node_id".to_owned(),
                });
            }
            Ok(QuicClusterStream {
                node_id: hello.node_id,
                protocol: hello.protocol,
                master_highest_log_seq: hello.last_acked_log_seq,
                recv: stream,
                buffer,
                session: QuicH3Session {
                    conn,
                    send_request,
                    driver: driver_handle,
                },
            })
        }
        StreamRecord::Error { error } => Err(crate::client::map_wire_error_public(&error)),
        _ => Err(ClusterError::TransportQuic {
            message: "master did not start the stream with hello".to_owned(),
        }),
    }
}

fn quic_client_tls(identity: &NodeIdentity) -> Result<rustls::ClientConfig, ClusterError> {
    let mut roots = RootCertStore::empty();
    let ca =
        CertificateDer::from_pem_slice(identity.ca_cert_pem().as_bytes()).map_err(|error| {
            ClusterError::TransportQuic {
                message: format!("cluster CA PEM: {error}"),
            }
        })?;
    roots.add(ca).map_err(|error| ClusterError::TransportQuic {
        message: format!("cluster CA root: {error}"),
    })?;

    let certs = CertificateDer::pem_slice_iter(identity.node_cert_pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ClusterError::TransportQuic {
            message: format!("node certificate PEM: {error}"),
        })?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key().serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| ClusterError::TransportQuic {
            message: format!("TLS 1.3: {error}"),
        })?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|error| ClusterError::TransportQuic {
            message: format!("node certificate/key: {error}"),
        })?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(tls)
}

fn quic_authority(
    master_url: &str,
) -> Result<(SocketAddr, ServerName<'static>, String), ClusterError> {
    let authority = master_url
        .strip_prefix("https://")
        .ok_or_else(|| ClusterError::RoleInvalid {
            reason: "master_url must be https://".to_owned(),
        })?
        .split('/')
        .next()
        .ok_or_else(|| ClusterError::RoleInvalid {
            reason: "master_url authority missing".to_owned(),
        })?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>().map_err(|_| ClusterError::RoleInvalid {
                reason: "master_url port invalid".to_owned(),
            })?,
        ),
        None => (authority, 443),
    };
    let ip: IpAddr = host.parse().map_err(|_| ClusterError::RoleInvalid {
        reason: "master_url host must be an IP for QUIC dial".to_owned(),
    })?;
    let addr = SocketAddr::new(ip, port);
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
        ClusterError::RoleInvalid {
            reason: "master_url SNI invalid".to_owned(),
        }
    })?;
    Ok((addr, server_name, host.to_owned()))
}

fn node_id_from_pem(cert_pem: &str) -> Result<String, ClusterError> {
    let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|error| {
        ClusterError::TransportQuic {
            message: format!("node certificate PEM: {error}"),
        }
    })?;
    crate::ca::node_id_from_der(der.as_ref()).ok_or(ClusterError::TransportQuic {
        message: "node certificate has no node_id DNS SAN".to_owned(),
    })
}

pub(crate) async fn read_line_h3(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    buffer: &mut Vec<u8>,
) -> Result<Vec<u8>, ClusterError> {
    loop {
        if let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = buffer.drain(..=position).collect();
            line.pop();
            return Ok(line);
        }
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                buffer.extend_from_slice(chunk.chunk());
                chunk.advance(chunk.remaining());
            }
            Ok(None) if !buffer.is_empty() => return Ok(std::mem::take(buffer)),
            Ok(None) => return Err(ClusterError::MasterUnavailable),
            Err(_) => return Err(ClusterError::MasterUnavailable),
        }
    }
}
