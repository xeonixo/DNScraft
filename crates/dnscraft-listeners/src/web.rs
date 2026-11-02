//! Hand-off of non-DNS HTTP requests on a local DoH listener (web UI / control API on `:443`).

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use ipnet::IpNet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Response body of a [`WebHandler`].
pub type WebBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Future returned by a [`WebHandler`].
pub type WebFuture = Pin<Box<dyn Future<Output = Response<WebBody>> + Send>>;

/// Serves one request (the TCP peer plus the raw request) that is not a DoH path.
pub type WebHandler = Arc<dyn Fn(SocketAddr, Request<Incoming>) -> WebFuture + Send + Sync>;

/// Late-bound [`WebHandler`] shared by the DoH listeners of a [`crate::ListenerSet`].
///
/// The control API is built after the listeners start, so the slot is filled once it is ready.
/// While it is empty (or never filled) every non-DoH path answers `404`, as before.
///
/// `public` additionally lets non-private sources reach the handler on a public-exposure listener;
/// it is off by default and can be flipped at runtime. `cidrs` is an optional allowlist for those
/// public sources: empty means no extra restriction.
#[derive(Default)]
pub struct WebSlot {
    handler: OnceLock<WebHandler>,
    public: AtomicBool,
    cidrs: RwLock<Vec<IpNet>>,
}

impl WebSlot {
    /// Installs the handler; returns `false` when one is already installed.
    pub fn set(&self, handler: WebHandler) -> bool {
        self.handler.set(handler).is_ok()
    }

    /// Allows (or stops allowing) public sources to reach the handler; takes effect immediately.
    pub fn set_public(&self, enabled: bool) {
        self.public.store(enabled, Ordering::Relaxed);
    }

    /// Whether public sources may reach the handler.
    pub fn public(&self) -> bool {
        self.public.load(Ordering::Relaxed)
    }

    /// Replaces the public-source CIDR allowlist. An empty list adds no extra restriction.
    pub fn set_public_cidrs(&self, cidrs: Vec<IpNet>) {
        *self
            .cidrs
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cidrs;
    }

    /// Whether a public source is inside the allowlist.
    ///
    /// An empty list allows every address. A non-empty list allows `ip` only when it
    /// falls in one of the networks.
    pub fn allows_public_cidr(&self, ip: IpAddr) -> bool {
        let cidrs = self
            .cidrs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cidrs.is_empty() || cidrs.iter().any(|net| net.contains(&ip))
    }

    pub(crate) fn get(&self) -> Option<&WebHandler> {
        self.handler.get()
    }
}

/// Parses a public-web CIDR allowlist.
///
/// An empty iterator is valid and means no extra restriction. Blank entries and
/// anything that is not a CIDR (host bits included) are rejected.
pub fn parse_public_cidrs<I, S>(cidrs: I) -> Result<Vec<IpNet>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut nets = Vec::new();
    for cidr in cidrs {
        let text = cidr.as_ref().trim();
        if text.is_empty() {
            return Err("empty CIDR".to_owned());
        }
        let net = text
            .parse::<IpNet>()
            .map_err(|_| format!("`{text}` is not a CIDR"))?;
        nets.push(net);
    }
    Ok(nets)
}
