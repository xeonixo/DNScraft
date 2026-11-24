//! Normalize assistant- or user-supplied domain inputs.
//!
//! Agents often paste a full URL (`https://www.instagram.com/p/…`) or a bare
//! host. Tool handlers call [`canonicalize_user_domain`] so the rest of the
//! pipeline always sees a filtering-canonical name.

use crate::protected::canonicalize;

/// Extract a hostname from a URL or host-like string, then canonicalize it.
///
/// Accepts:
/// - bare domains (`Example.COM.`)
/// - URLs with a scheme (`https://www.instagram.com/reel/xyz?x=1`)
/// - scheme-less paths (`instagram.com/p/1`)
///
/// Returns the same filtering-namespace codes as [`canonicalize`].
pub fn canonicalize_user_domain(raw: &str) -> Result<String, &'static str> {
    let host = extract_host(raw).unwrap_or_else(|| raw.trim().to_owned());
    if host.is_empty() {
        return Err("filter_name.empty");
    }
    canonicalize(&host)
}

/// Whether `raw` looks like a URL or dotted domain rather than an app name.
pub fn looks_like_domain_or_url(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty() {
        return false;
    }
    if s.contains("://") || s.starts_with("//") {
        return true;
    }
    // host/path or host:port without spaces
    if !s.contains(char::is_whitespace)
        && (s.contains('/') || s.contains('?') || s.contains('#'))
        && s.contains('.')
    {
        return true;
    }
    // dotted hostname (instagram.com) — not a single app token
    s.contains('.') && !s.contains(char::is_whitespace)
}

/// Pull the host out of a URL-like string. Returns `None` when there is no
/// usable host segment (caller should fall back to the raw trim).
pub fn extract_host(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() {
        return None;
    }

    let after_scheme = if let Some(rest) = s.strip_prefix("//") {
        rest
    } else if let Some(idx) = s.find("://") {
        &s[idx + 3..]
    } else if needs_host_split(s) {
        s
    } else {
        return None;
    };

    let hostport = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() {
        return None;
    }
    let hostport = hostport.rsplit('@').next().unwrap_or(hostport);
    let host = strip_port(hostport);
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_owned())
}

fn needs_host_split(s: &str) -> bool {
    !s.contains(char::is_whitespace)
        && s.contains('.')
        && (s.contains('/') || s.contains('?') || s.contains('#'))
}

fn strip_port(hostport: &str) -> &str {
    if let Some(inner) = hostport.strip_prefix('[') {
        return inner.split(']').next().unwrap_or(inner);
    }
    // Only strip :port when there is a single colon (not IPv6).
    if hostport.chars().filter(|c| *c == ':').count() == 1 {
        return hostport.split(':').next().unwrap_or(hostport);
    }
    hostport
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn url_with_path_and_query() {
        assert_eq!(
            canonicalize_user_domain("https://www.Instagram.com/p/abc?utm=1").unwrap(),
            "www.instagram.com"
        );
    }

    #[test]
    fn scheme_less_path() {
        assert_eq!(
            canonicalize_user_domain("instagram.com/reel/1").unwrap(),
            "instagram.com"
        );
    }

    #[test]
    fn bare_domain_still_works() {
        assert_eq!(
            canonicalize_user_domain("  Example.COM. ").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn app_name_is_not_a_url() {
        assert!(!looks_like_domain_or_url("Instagram"));
        assert!(looks_like_domain_or_url("instagram.com"));
        assert!(looks_like_domain_or_url("https://x.test/y"));
    }

    #[test]
    fn extract_host_strips_userinfo_and_port() {
        assert_eq!(
            extract_host("https://user:pass@cdn.example.net:443/a").as_deref(),
            Some("cdn.example.net")
        );
    }
}
