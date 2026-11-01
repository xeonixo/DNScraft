//! Network helper functions.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Resolves the client address behind a reverse proxy.
///
/// When `peer` is not in `trusted`, returns `peer` (spoofed
/// `X-Forwarded-For` from untrusted clients is ignored). When `peer` is
/// trusted, walks `x_forwarded_for` from the right (the hop closest to us)
/// and returns the first address that is not itself trusted. The leftmost
/// entries are client-controlled and are never trusted alone. A missing
/// header, a malformed entry, or a list made only of trusted proxies falls
/// back to `peer`.
pub fn client_ip_from_forwarded_for(
    peer: IpAddr,
    trusted: &[IpAddr],
    x_forwarded_for: Option<&str>,
) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.iter().any(|ip| ip.to_canonical() == peer) {
        return peer;
    }
    let Some(raw) = x_forwarded_for else {
        return peer;
    };
    for entry in raw.rsplit(',') {
        let Ok(ip) = entry.trim().parse::<IpAddr>() else {
            return peer;
        };
        let ip = ip.to_canonical();
        if !trusted.iter().any(|t| t.to_canonical() == ip) {
            return ip;
        }
    }
    peer
}

/// Whether the host portion of a URL is loopback (`localhost` or an IP loopback).
pub fn is_loopback_host_str(rest: &str) -> bool {
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// IPv4 private / special-use (RFC 1918, loopback, link-local, CGNAT, this-network, broadcast).
pub fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || is_this_network(v4)
        || is_cgnat(v4)
}

/// Whether an address may be treated as private (used for rebind protection, etc.).
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    if let Some(v4) = nat64_embedded_v4(v6) {
        return is_private_v4(v4);
    }
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local() || v6.is_unspecified()
}

/// Shared address space `100.64.0.0/10` (RFC 6598).
pub fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn nat64_embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = v6.octets();
    if o[0] == 0x00
        && o[1] == 0x64
        && o[2] == 0xff
        && o[3] == 0x9b
        && o[4..12].iter().all(|&b| b == 0)
    {
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        None
    }
}

fn is_this_network(v4: Ipv4Addr) -> bool {
    v4.octets()[0] == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host_str("127.0.0.1:8443/"));
        assert!(is_loopback_host_str("[::1]:8443/"));
        assert!(is_loopback_host_str("localhost:8080/path"));
        assert!(!is_loopback_host_str("192.0.2.1:443/"));
    }

    #[test]
    fn classifies_private_v4() {
        assert!(is_private_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::LOCALHOST));
        assert!(is_private_v4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_v4(Ipv4Addr::BROADCAST));
        assert!(!is_private_v4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn classifies_cgnat() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn classifies_private_ip() {
        assert!(is_private(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_private(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(is_private(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn forwarded_for_ignores_untrusted_peer() {
        let peer = "203.0.113.5".parse::<IpAddr>().unwrap();
        assert_eq!(
            client_ip_from_forwarded_for(peer, &[], Some("198.51.100.7")),
            peer
        );
    }

    #[test]
    fn forwarded_for_honours_trusted_proxy() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(
            client_ip_from_forwarded_for(peer, &[peer], Some("198.51.100.7, 10.0.0.1")),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_for_skips_spoofed_leftmost_and_chained_proxies() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        let inner = "10.0.0.2".parse::<IpAddr>().unwrap();
        assert_eq!(
            client_ip_from_forwarded_for(
                peer,
                &[peer],
                Some("192.0.2.66, 198.51.100.7, 10.0.0.1"),
            ),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip_from_forwarded_for(
                peer,
                &[peer, inner],
                Some("198.51.100.7, 10.0.0.2, 10.0.0.1"),
            ),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_for_falls_back_on_malformed_or_all_trusted() {
        let peer = "10.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(
            client_ip_from_forwarded_for(peer, &[peer], Some("not-an-ip")),
            peer
        );
        assert_eq!(
            client_ip_from_forwarded_for(peer, &[peer], Some("10.0.0.1, 10.0.0.1")),
            peer
        );
        assert_eq!(client_ip_from_forwarded_for(peer, &[peer], None), peer);
    }
}
