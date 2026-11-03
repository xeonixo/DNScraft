//! DoH over HTTP/3 (RFC 8484 / RFC 9114) on UDP with ALPN `h3`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use dnscraft_tls::CertResolver;
use http::header;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime, VarInt};
use rustls::ServerConfig as RustlsServerConfig;
use rustls_pki_types::CertificateDer as CertDer;
use std::sync::OnceLock;
use tokio::sync::{Notify, Semaphore, oneshot, watch};

use crate::admission::Admission;
use crate::clock::{Clock, add_duration, wait_until};
use crate::cluster_slot::{
    ClusterAttachment, MuxCertResolver, cluster_sni_selected, colocated_quic_server_config,
};
use crate::config::{Limits, ListenerConfig};
use crate::doh::{
    ConnActivity, DohShared, DohStats, effective_doh_source, needs_address_validation,
    process_doh_request, release_per_source, resolve_path_client_id,
};
use crate::doh_request::MAX_DOH_HEADER_LIST_SIZE;
use crate::doh_request::parse_doh_path;
use crate::error::ListenersError;
use crate::events::QueryEventSink;
use crate::framing::MAX_MESSAGE_LEN;
use crate::handler::QueryHandler;
use crate::socket::bind_udp;
use crate::tls::{
    ALPN_H3, ListenerCertResolver, SniGate, TlsStats, apply_tls_handshake_strike,
    quic_server_config,
};

/// Application close when the per-connection stream cap is exceeded (same idea as DoQ).
const H3_EXCESSIVE_LOAD: VarInt = VarInt::from_u32(0x101);

/// Inputs for [`serve_doh_h3`].
pub struct DohH3ServeParams<H: ?Sized> {
    /// Listener id / bind / exposure (`h3` should be true).
    pub listener: ListenerConfig,
    /// Shared limits (QUIC stream cap, idle = `tcp_idle_timeout`).
    pub limits: Limits,
    /// Shared admission across listeners.
    pub admission: Arc<Mutex<Admission>>,
    /// Policy or test handler.
    pub handler: Arc<H>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Shared with the TCP DoH listener.
    pub stats: Arc<DohStats>,
    /// TLS counters.
    pub tls_stats: Arc<TlsStats>,
    /// Hot-reloadable certificates.
    pub certs: Arc<CertResolver>,
    /// Path Client-ID registry (same gate as HTTP/2 DoH).
    pub sni_gate: Arc<SniGate>,
    /// Query-log sink.
    pub event_sink: Option<Arc<dyn QueryEventSink>>,
    /// Filled with the bound UDP port for TCP `Alt-Svc`.
    pub alt_svc_port: Arc<AtomicU16>,
    /// Reverse-proxy addresses whose `X-Forwarded-For` is honoured for DoH attribution.
    pub trusted_proxies: Arc<std::sync::RwLock<Vec<IpAddr>>>,
    /// Optional cluster attachment (SNI demux for DoH-h3 and Cluster-h3).
    pub cluster: Arc<crate::cluster_slot::ClusterSlot>,
    /// Bound address (port 0 friendly).
    pub bound: oneshot::Sender<SocketAddr>,
    /// Stop accepting.
    pub shutdown: watch::Receiver<bool>,
}

struct DohH3Shared<H: ?Sized> {
    doh: Arc<DohShared<H>>,
    tls_stats: Arc<TlsStats>,
    certs: Arc<CertResolver>,
    conn_cap: Arc<Semaphore>,
}

/// Runs DoH over HTTP/3 until `params.shutdown` is true.
///
/// Binds UDP via [`bind_udp`], ALPN `h3` only, 0-RTT off. Path / admission rules
/// match [`crate::serve_doh`].
pub async fn serve_doh_h3<H>(params: DohH3ServeParams<H>) -> Result<(), ListenersError>
where
    H: QueryHandler + 'static,
{
    let DohH3ServeParams {
        listener,
        limits,
        admission,
        handler,
        clock,
        stats,
        tls_stats,
        certs,
        sni_gate,
        event_sink,
        alt_svc_port,
        trusted_proxies,
        cluster,
        bound,
        mut shutdown,
    } = params;

    let std_sock = bind_udp(listener.address)?;
    let local = std_sock
        .local_addr()
        .map_err(|e| ListenersError::bind(listener.address, e))?;
    alt_svc_port.store(local.port(), Ordering::Relaxed);
    let _ = bound.send(local);

    let resolver = ListenerCertResolver::local(Arc::clone(&certs), Arc::clone(&tls_stats));
    let tls_policy = listener.tls_policy.clone().unwrap_or_default();
    let mut rustls_cfg: RustlsServerConfig = (*quic_server_config(resolver, &tls_policy)).clone();
    rustls_cfg.alpn_protocols = vec![ALPN_H3.to_vec()];

    let server_config = quinn_server_config(rustls_cfg, &limits)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(TokioRuntime),
    )
    .map_err(|e| ListenersError::bind(listener.address, e))?;

    let conn_cap_n = limits.max_connections_per_listener.max(1);
    let conn_cap = Arc::new(Semaphore::new(conn_cap_n as usize));
    let inflight = Arc::new(Semaphore::new(
        limits.max_inflight_per_listener.max(1) as usize
    ));
    let doh = Arc::new(DohShared {
        admission,
        listener,
        limits: limits.clone(),
        handler,
        clock,
        stats,
        sni_gate,
        conn_cap: Arc::clone(&conn_cap),
        inflight,
        per_source: Mutex::new(HashMap::new()),
        event_sink,
        alt_svc_port,
        web: Arc::default(),
        cluster,
        colocated_acceptor: OnceLock::new(),
        trusted_proxies,
        shutdown: shutdown.clone(),
    });
    let shared = Arc::new(DohH3Shared {
        doh,
        tls_stats,
        certs,
        conn_cap,
    });
    let colocated_quic = OnceLock::new();

    loop {
        maybe_install_colocated_quic(&endpoint, &shared, &colocated_quic);
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    // Stop accepting; connections drain in-flight requests and
                    // release their permits, then the endpoint is closed.
                    let _ = shared.conn_cap.acquire_many(conn_cap_n).await;
                    endpoint.close(VarInt::from_u32(0), b"shutdown");
                    return Ok(());
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return Ok(());
                };
                handle_incoming(Arc::clone(&shared), incoming);
            }
        }
    }
}

/// Transport idle for a DoH-only QUIC endpoint (`tcp_idle_timeout`).
fn quinn_server_config(
    rustls_cfg: RustlsServerConfig,
    limits: &Limits,
) -> Result<ServerConfig, ListenersError> {
    quinn_server_config_with_idle(rustls_cfg, limits, limits.tcp_idle_timeout)
}

/// When cluster Prefer-QUIC shares UDP/443, heartbeats stay on TCP/HTTP/2, so the
/// NDJSON stream itself is quiet. A transport idle equal to DoH's 10s app idle
/// tears the stream down every heartbeat interval. Keep transport idle longer;
/// DoH still closes via application idle in [`serve_h3`].
const COLOCATED_QUIC_TRANSPORT_IDLE: Duration = Duration::from_secs(120);

fn quinn_server_config_with_idle(
    rustls_cfg: RustlsServerConfig,
    limits: &Limits,
    idle: Duration,
) -> Result<ServerConfig, ListenersError> {
    let quic_crypto =
        QuicServerConfig::try_from(rustls_cfg).map_err(|e| ListenersError::TlsHandshake {
            message: format!("QuicServerConfig: {e}"),
        })?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(
        limits.max_quic_streams_per_connection.max(1),
    ));
    transport.max_concurrent_uni_streams(VarInt::from_u32(3));
    let idle_timeout = idle.try_into().map_err(|_| {
        ListenersError::config(format!(
            "QUIC transport idle {idle:?} is not a valid IdleTimeout"
        ))
    })?;
    transport.max_idle_timeout(Some(idle_timeout));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

/// Switches the shared UDP/443 endpoint to muxed cluster+DoH TLS once attached.
fn maybe_install_colocated_quic<H: ?Sized>(
    endpoint: &Endpoint,
    shared: &DohH3Shared<H>,
    installed: &OnceLock<()>,
) {
    if installed.get().is_some() {
        return;
    }
    let Some(attachment) = shared.doh.cluster.get() else {
        return;
    };
    match build_colocated_quic_server_config(attachment, &shared.certs, &shared.tls_stats, &shared.doh.limits)
    {
        Ok(config) => {
            endpoint.set_server_config(Some(config));
            let _ = installed.set(());
            tracing::info!(
                sni = %attachment.cluster_sni,
                listener = %shared.doh.listener.id,
                "DoH-h3 endpoint colocating cluster control plane (SNI demux on UDP/443)"
            );
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "cluster QUIC colocation TLS setup failed; UDP/443 stays DoH-only"
            );
            // Avoid retrying every accept with the same broken PEMs.
            let _ = installed.set(());
        }
    }
}

fn build_colocated_quic_server_config(
    attachment: &ClusterAttachment,
    certs: &Arc<CertResolver>,
    tls_stats: &Arc<TlsStats>,
    limits: &Limits,
) -> Result<ServerConfig, String> {
    let doh: Arc<dyn rustls::server::ResolvesServerCert> =
        ListenerCertResolver::local(Arc::clone(certs), Arc::clone(tls_stats));
    let cluster_key = MuxCertResolver::certified_key_from_pem(
        &attachment.server_cert_pem,
        &attachment.server_key_pem,
    )?;
    let mux = MuxCertResolver::new(doh, attachment.cluster_sni.clone(), cluster_key);
    let rustls_cfg = (*colocated_quic_server_config(mux, &attachment.ca_cert_pem)?).clone();
    quinn_server_config_with_idle(rustls_cfg, limits, COLOCATED_QUIC_TRANSPORT_IDLE)
        .map_err(|e| e.to_string())
}

fn handle_incoming<H>(shared: Arc<DohH3Shared<H>>, incoming: quinn::Incoming)
where
    H: QueryHandler + 'static,
{
    let peer = incoming.remote_address();
    let source = peer.ip().to_canonical();
    // Unvalidated public source: Retry before any state, so spoofed sources cannot hold
    // permits or cause handshake strikes.
    if needs_address_validation(
        &shared.doh.admission,
        shared.doh.listener.exposure,
        source,
        incoming.remote_address_validated(),
    ) {
        if let Err(e) = incoming.retry() {
            e.into_incoming().ignore();
        }
        return;
    }

    {
        let now = shared.doh.clock.now();
        let mut adm = shared
            .doh
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if adm.is_banned(source, now) {
            DohStats::bump(&shared.doh.stats.dropped_banned);
            incoming.refuse();
            return;
        }
    }

    let Ok(conn_permit) = shared.conn_cap.clone().try_acquire_owned() else {
        DohStats::bump(&shared.doh.stats.rejected_conn_cap);
        incoming.refuse();
        return;
    };

    {
        let mut map = shared
            .doh
            .per_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = map.entry(source).or_insert(0);
        if *count >= shared.doh.limits.max_connections_per_source {
            DohStats::bump(&shared.doh.stats.rejected_per_source);
            drop(conn_permit);
            incoming.refuse();
            return;
        }
        *count += 1;
    }

    if !shared.certs.has_cert() {
        TlsStats::bump(&shared.tls_stats.no_cert);
        drop(conn_permit);
        release_per_source(&shared.doh.per_source, source);
        incoming.refuse();
        return;
    }

    tokio::spawn(async move {
        let _conn_permit = conn_permit;
        let handshake_timeout = shared.doh.limits.tls_handshake_timeout;
        let exposure = shared.doh.listener.exposure;
        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(_) => {
                TlsStats::bump(&shared.tls_stats.handshake_fail);
                strike_handshake(&shared, exposure, source);
                release_per_source(&shared.doh.per_source, source);
                DohStats::bump(&shared.doh.stats.closed);
                return;
            }
        };

        let deadline = add_duration(shared.doh.clock.now(), handshake_timeout);
        let wake = Notify::new();
        let conn = tokio::select! {
            r = connecting => match r {
                Ok(c) => c,
                Err(_) => {
                    TlsStats::bump(&shared.tls_stats.handshake_fail);
                    strike_handshake(&shared, exposure, source);
                    release_per_source(&shared.doh.per_source, source);
                    DohStats::bump(&shared.doh.stats.closed);
                    return;
                }
            },
            () = wait_until(shared.doh.clock.as_ref(), deadline, &wake) => {
                TlsStats::bump(&shared.tls_stats.handshake_timeouts);
                strike_handshake(&shared, exposure, source);
                release_per_source(&shared.doh.per_source, source);
                DohStats::bump(&shared.doh.stats.closed);
                return;
            }
        };

        DohStats::bump(&shared.doh.stats.accepted);
        let cluster_sni = shared
            .doh
            .cluster
            .get()
            .map(|attachment| attachment.cluster_sni.as_str());
        let sni = conn
            .handshake_data()
            .and_then(|data| {
                data.downcast_ref::<HandshakeData>()
                    .map(|handshake| handshake.server_name.clone())
            })
            .flatten();
        let is_cluster = cluster_sni
            .is_some_and(|name| cluster_sni_selected(name, sni.as_deref()));
        if is_cluster {
            serve_cluster_h3(Arc::clone(&shared), conn, peer).await;
        } else {
            serve_h3(Arc::clone(&shared), conn, peer).await;
        }
        release_per_source(&shared.doh.per_source, source);
        DohStats::bump(&shared.doh.stats.closed);
    });
}

fn strike_handshake<H: ?Sized>(
    shared: &DohH3Shared<H>,
    exposure: crate::config::Exposure,
    source: IpAddr,
) {
    let mut adm = shared
        .doh
        .admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    apply_tls_handshake_strike(&mut adm, exposure, source, shared.doh.clock.now());
}

fn peer_cert_der(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let certs = conn.peer_identity()?.downcast::<Vec<CertDer>>().ok()?;
    certs.first().map(|der| der.as_ref().to_vec())
}

/// Serves `/cluster/v1/*` over HTTP/3 on the shared DoH UDP endpoint (cluster SNI).
async fn serve_cluster_h3<H>(shared: Arc<DohH3Shared<H>>, conn: quinn::Connection, peer: SocketAddr)
where
    H: QueryHandler + 'static,
{
    let Some(attachment) = shared.doh.cluster.get().cloned() else {
        conn.close(VarInt::from_u32(0), b"no cluster");
        return;
    };
    let peer_cert = peer_cert_der(&conn);
    let mut h3_builder = h3::server::builder();
    h3_builder.max_field_section_size(MAX_DOH_HEADER_LIST_SIZE);
    let mut h3_conn = match h3_builder
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
                let attachment = attachment.clone();
                let peer_cert = peer_cert.clone();
                // Bound the request-body read only; the NDJSON response may sit quiet.
                let body_timeout = shared.doh.limits.tcp_idle_timeout;
                tokio::spawn(async move {
                    let _ = dispatch_cluster_h3(
                        resolver,
                        attachment,
                        peer,
                        peer_cert,
                        body_timeout,
                    )
                    .await;
                });
            }
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

async fn dispatch_cluster_h3(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    attachment: ClusterAttachment,
    peer: SocketAddr,
    peer_cert: Option<Vec<u8>>,
    body_timeout: Duration,
) -> Result<(), ()> {
    let (req, mut stream) = resolver.resolve_request().await.map_err(|_| ())?;
    let (parts, ()) = req.into_parts();
    if !ClusterAttachment::is_cluster_path(parts.uri.path()) {
        let resp = http::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .map_err(|_| ())?;
        stream.send_response(resp).await.map_err(|_| ())?;
        stream.finish().await.map_err(|_| ())?;
        return Ok(());
    }

    // Cap stalled /cluster uploads; leave the response stream uncapped so Prefer-QUIC
    // NDJSON can stay quiet between pushes (keep-alive holds the QUIC connection).
    let mut body = Vec::new();
    let body_read = async {
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    // Cluster H3 currently carries stream hello / small POSTs only.
                    const MAX_CLUSTER_H3_BODY: usize = 256 * 1024;
                    if body.len().saturating_add(chunk.remaining()) > MAX_CLUSTER_H3_BODY {
                        return Err(());
                    }
                    body.extend_from_slice(chunk.chunk());
                    chunk.advance(chunk.remaining());
                }
                Ok(None) => return Ok(()),
                Err(_) => return Err(()),
            }
        }
    };
    match tokio::time::timeout(body_timeout, body_read).await {
        Ok(Ok(())) => {}
        _ => return Err(()),
    }
    let request = Request::from_parts(parts, Bytes::from(body));
    let response = (attachment.handler)(peer, peer_cert, request).await;
    let (parts, mut body) = response.into_parts();
    let mut builder = http::Response::builder().status(parts.status);
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

async fn serve_h3<H>(shared: Arc<DohH3Shared<H>>, conn: quinn::Connection, peer: SocketAddr)
where
    H: QueryHandler + 'static,
{
    let mut h3_builder = h3::server::builder();
    h3_builder.max_field_section_size(MAX_DOH_HEADER_LIST_SIZE);
    let mut h3_conn = match h3_builder
        .build(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(c) => c,
        Err(_) => {
            conn.close(VarInt::from_u32(0), b"h3");
            return;
        }
    };

    let stream_cap = Arc::new(Semaphore::new(
        shared.doh.limits.max_quic_streams_per_connection.max(1) as usize,
    ));
    let idle = shared.doh.limits.tcp_idle_timeout;
    let activity = Arc::new(ConnActivity::new(shared.doh.clock.now()));
    let mut listener_shutdown = shared.doh.shutdown.clone();
    let mut draining = *listener_shutdown.borrow();

    loop {
        let deadline = add_duration(activity.last_activity(), idle);
        let in_flight = activity.in_flight();
        if draining && in_flight == 0 {
            conn.close(VarInt::from_u32(0), b"shutdown");
            return;
        }
        tokio::select! {
            changed = listener_shutdown.changed() => {
                if changed.is_err() || *listener_shutdown.borrow() {
                    draining = true;
                }
            }
            accepted = h3_conn.accept(), if !draining => {
                match accepted {
                    Ok(Some(resolver)) => {
                        activity.touch(shared.doh.clock.as_ref());
                        let Ok(permit) = stream_cap.clone().try_acquire_owned() else {
                            conn.close(H3_EXCESSIVE_LOAD, b"stream cap");
                            return;
                        };
                        let shared = Arc::clone(&shared);
                        let activity = Arc::clone(&activity);
                        tokio::spawn(async move {
                            let _permit = permit;
                            activity.begin();
                            let clock = Arc::clone(&shared.doh.clock);
                            let result =
                                handle_h3_request(Arc::clone(&shared), resolver, peer.ip()).await;
                            if result.is_err() {
                                DohStats::bump(&shared.doh.stats.request_errors);
                            }
                            activity.finish();
                            activity.touch(clock.as_ref());
                        });
                    }
                    Ok(None) => return,
                    Err(_) => return,
                }
            }
            // Re-evaluate idle when a request finishes (in_flight -> 0) or
            // activity changes, so a stalled request that just timed out does
            // not leave the connection blocked on accept() forever.
            () = activity.notified() => {}
            () = wait_until(shared.doh.clock.as_ref(), deadline, activity.wake()), if in_flight == 0 && !draining => {
                if activity.in_flight() == 0
                    && shared.doh.clock.now() >= deadline
                {
                    conn.close(VarInt::from_u32(0), b"idle");
                    return;
                }
            }
        }
    }
}

async fn handle_h3_request<H>(
    shared: Arc<DohH3Shared<H>>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    peer: IpAddr,
) -> Result<(), ()>
where
    H: QueryHandler,
{
    // Per-request read budget covering header + body read, like DoQ. A client
    // that sends HEADERS and stalls must not hold the connection open past this.
    // `tcp_idle_timeout` is the only suitable limit (no request-timeout setting
    // exists): it is the same window DoH/TCP apply to a non-progressing peer.
    // The budget is a single total window, not reset per chunk — progress below
    // it is allowed, but a request that never finishes is killed once it elapses.
    let read_deadline = add_duration(shared.doh.clock.now(), shared.doh.limits.tcp_idle_timeout);
    let read_wake = Notify::new();

    let (req, mut stream) = tokio::select! {
        r = resolver.resolve_request() => r.map_err(|_| ())?,
        () = wait_until(shared.doh.clock.as_ref(), read_deadline, &read_wake) => {
            DohStats::bump(&shared.doh.stats.request_timeouts);
            return Ok(());
        }
    };
    let (parts, ()) = req.into_parts();
    let (source, peer_ip) = effective_doh_source(&shared.doh, peer, &parts.headers);

    // Path / Client-ID gate before reading the body (same as HTTP/2 and HTTP/1.1).
    let client_id_state =
        match resolve_path_client_id(&shared.doh, source, &parse_doh_path(parts.uri.path())) {
            Ok(state) => state,
            Err(status) => {
                let resp = http::Response::builder()
                    .status(status)
                    .body(())
                    .map_err(|_| ())?;
                stream.send_response(resp).await.map_err(|_| ())?;
                stream.finish().await.map_err(|_| ())?;
                return Ok(());
            }
        };

    let mut body = Vec::new();
    loop {
        let mut chunk = tokio::select! {
            r = stream.recv_data() => match r {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => return Err(()),
            },
            () = wait_until(shared.doh.clock.as_ref(), read_deadline, &read_wake) => {
                // Reset the stalled stream and count it; the caller decrements
                // in_flight afterwards so the connection can still go idle.
                stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                DohStats::bump(&shared.doh.stats.request_timeouts);
                return Ok(());
            }
        };
        body.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
        if body.len() > MAX_MESSAGE_LEN {
            crate::doh::strike_malformed(&shared.doh, source);
            let resp = http::Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .map_err(|_| ())?;
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
            return Ok(());
        }
    }

    // Reconstruct a Request<()> for method/uri/headers; body is separate.
    let req = Request::from_parts(parts, ());
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // GET has empty body; POST carries dns-message.
    let body_bytes = if method == Method::GET {
        Bytes::new()
    } else {
        Bytes::from(body)
    };

    let mut out = process_doh_request(
        &shared.doh,
        source,
        peer_ip,
        client_id_state,
        &method,
        &uri,
        &headers,
        body_bytes,
    )
    .await;

    // The response already travels over HTTP/3, so Alt-Svc is redundant; the
    // HTTP/2 DoH listener advertises the UDP port instead.
    out.headers.remove(header::ALT_SVC);

    let mut builder = http::Response::builder().status(out.status);
    for (name, value) in out.headers.iter() {
        builder = builder.header(name, value);
    }
    let resp = builder.body(()).map_err(|_| ())?;
    stream.send_response(resp).await.map_err(|_| ())?;
    if !out.body.is_empty() {
        stream.send_data(out.body).await.map_err(|_| ())?;
    }
    stream.finish().await.map_err(|_| ())?;
    Ok(())
}
