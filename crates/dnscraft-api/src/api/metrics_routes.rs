//! Prometheus text exposition for process counters (`GET /metrics`).
//!
//! Hand-written OpenMetrics/Prometheus 0.0.4 text so the control-api stays
//! free of a metrics crate while SPEC.md still lists Prometheus under Later.
//! Scrapers authenticate as a viewer/admin principal (same posture as stats
//! reads). Missing engines simply omit their metric families.

use std::fmt::Write as _;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::server::AppState;

/// `GET /metrics`: Prometheus text body for the wired engines.
pub(crate) async fn metrics(State(state): State<AppState>) -> Response {
    let body = render_prometheus(&state);
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// Builds the Prometheus exposition from whatever engines are attached.
pub(crate) fn render_prometheus(state: &AppState) -> String {
    let mut out = String::with_capacity(2_048);
    out.push_str("# HELP dnscraft_up Always 1 when the control-api answers /metrics.\n");
    out.push_str("# TYPE dnscraft_up gauge\n");
    out.push_str("dnscraft_up 1\n");

    if let Some(resolver) = state.resolver() {
        let s = resolver.stats();
        metric_help(
            &mut out,
            "dnscraft_resolver_resolutions_total",
            "counter",
            "Questions passed to resolve (local RFC 6303 answers excluded).",
        );
        writeln!(out, "dnscraft_resolver_resolutions_total {}", s.resolutions).ok();
        metric_help(
            &mut out,
            "dnscraft_resolver_outgoing_queries_total",
            "counter",
            "Queries sent to authoritative or forward-target servers.",
        );
        writeln!(
            out,
            "dnscraft_resolver_outgoing_queries_total {}",
            s.outgoing_queries
        )
        .ok();
        metric_help(
            &mut out,
            "dnscraft_resolver_cache_hits_total",
            "counter",
            "Fresh cache hits.",
        );
        writeln!(out, "dnscraft_resolver_cache_hits_total {}", s.cache_hits).ok();
        metric_help(
            &mut out,
            "dnscraft_resolver_stale_answers_total",
            "counter",
            "Answers served from expired cache entries (serve-stale).",
        );
        writeln!(
            out,
            "dnscraft_resolver_stale_answers_total {}",
            s.stale_answers
        )
        .ok();
        metric_help(
            &mut out,
            "dnscraft_resolver_dnssec_answers_total",
            "counter",
            "Successful answers by DNSSEC status.",
        );
        for (status, value) in [
            ("secure", s.dnssec_secure),
            ("insecure", s.dnssec_insecure),
            ("bogus", s.dnssec_bogus),
            ("indeterminate", s.dnssec_indeterminate),
        ] {
            writeln!(
                out,
                "dnscraft_resolver_dnssec_answers_total{{status=\"{status}\"}} {value}"
            )
            .ok();
        }
        metric_help(
            &mut out,
            "dnscraft_resolver_cache_entries",
            "gauge",
            "Entries currently held in the answer cache.",
        );
        writeln!(out, "dnscraft_resolver_cache_entries {}", s.cache_entries).ok();
        metric_help(
            &mut out,
            "dnscraft_resolver_resolve_latency_seconds_sum",
            "counter",
            "Sum of wall-clock seconds spent in counted resolve calls.",
        );
        writeln!(
            out,
            "dnscraft_resolver_resolve_latency_seconds_sum {:.9}",
            s.resolve_latency_ns as f64 / 1_000_000_000.0
        )
        .ok();
    }

    if let Some(filter) = state.filter_engine() {
        let stats = filter.stats();
        metric_help(
            &mut out,
            "dnscraft_filter_set_matches_total",
            "counter",
            "Match calls against a filter set.",
        );
        metric_help(
            &mut out,
            "dnscraft_filter_set_blocks_total",
            "counter",
            "Blocking or rewrite verdicts for a filter set.",
        );
        metric_help(
            &mut out,
            "dnscraft_filter_set_allows_total",
            "counter",
            "Allow verdicts for a filter set.",
        );
        for set in &stats.sets {
            let id = escape_label(set.set.as_str());
            writeln!(
                out,
                "dnscraft_filter_set_matches_total{{set=\"{id}\"}} {}",
                set.matches
            )
            .ok();
            writeln!(
                out,
                "dnscraft_filter_set_blocks_total{{set=\"{id}\"}} {}",
                set.blocks
            )
            .ok();
            writeln!(
                out,
                "dnscraft_filter_set_allows_total{{set=\"{id}\"}} {}",
                set.allows
            )
            .ok();
        }
        metric_help(
            &mut out,
            "dnscraft_filter_list_matches_total",
            "counter",
            "Match calls whose winning rule came from a list.",
        );
        for list in &stats.lists {
            let id = escape_label(list.list.as_str());
            writeln!(
                out,
                "dnscraft_filter_list_matches_total{{list=\"{id}\"}} {}",
                list.matches
            )
            .ok();
            writeln!(
                out,
                "dnscraft_filter_list_blocks_total{{list=\"{id}\"}} {}",
                list.blocks
            )
            .ok();
            writeln!(
                out,
                "dnscraft_filter_list_allows_total{{list=\"{id}\"}} {}",
                list.allows
            )
            .ok();
        }
    }

    if let Some(provider) = state.listeners_status() {
        let status = provider.listeners_status();
        metric_help(
            &mut out,
            "dnscraft_listener_queries_total",
            "counter",
            "Queries admitted into handling per listener.",
        );
        metric_help(
            &mut out,
            "dnscraft_listener_answered_total",
            "counter",
            "Answers successfully written per listener.",
        );
        metric_help(
            &mut out,
            "dnscraft_listener_dropped_total",
            "counter",
            "Drops before an answer per listener.",
        );
        metric_help(
            &mut out,
            "dnscraft_listener_rate_limited_total",
            "counter",
            "Rate-limit refusals per listener.",
        );
        metric_help(
            &mut out,
            "dnscraft_listener_banned_sources_total",
            "counter",
            "Admission drops because the source was banned.",
        );
        metric_help(
            &mut out,
            "dnscraft_listener_connections",
            "gauge",
            "Active connections (TCP / DoT / DoH / DoQ); UDP is always 0.",
        );
        for listener in &status.listeners {
            let id = escape_label(listener.id.as_str());
            let protocol = escape_label(listener.protocol.as_str());
            let labels = format!("listener=\"{id}\",protocol=\"{protocol}\"");
            writeln!(
                out,
                "dnscraft_listener_queries_total{{{labels}}} {}",
                listener.queries
            )
            .ok();
            writeln!(
                out,
                "dnscraft_listener_answered_total{{{labels}}} {}",
                listener.answered
            )
            .ok();
            writeln!(
                out,
                "dnscraft_listener_dropped_total{{{labels}}} {}",
                listener.dropped
            )
            .ok();
            writeln!(
                out,
                "dnscraft_listener_rate_limited_total{{{labels}}} {}",
                listener.rate_limited
            )
            .ok();
            writeln!(
                out,
                "dnscraft_listener_banned_sources_total{{{labels}}} {}",
                listener.banned_sources
            )
            .ok();
            writeln!(
                out,
                "dnscraft_listener_connections{{{labels}}} {}",
                listener.connections
            )
            .ok();
        }
        metric_help(
            &mut out,
            "dnscraft_listener_events_dropped_total",
            "counter",
            "Query events dropped by a full channel sink.",
        );
        writeln!(
            out,
            "dnscraft_listener_events_dropped_total {}",
            status.events_dropped
        )
        .ok();
        metric_help(
            &mut out,
            "dnscraft_listener_ban_entries",
            "gauge",
            "Ban / strike table entries in the shared admission state.",
        );
        writeln!(out, "dnscraft_listener_ban_entries {}", status.ban_entries).ok();
    }

    if let Some(log) = state.query_log() {
        metric_help(
            &mut out,
            "dnscraft_query_log_dropped_total",
            "counter",
            "Query-log rows dropped because the ingest channel was full.",
        );
        writeln!(
            out,
            "dnscraft_query_log_dropped_total {}",
            log.sink_dropped()
        )
        .ok();
        metric_help(
            &mut out,
            "dnscraft_query_log_stream_dropped_total",
            "counter",
            "Live query-log stream events dropped under back-pressure.",
        );
        writeln!(
            out,
            "dnscraft_query_log_stream_dropped_total {}",
            log.stream_dropped()
        )
        .ok();
    }

    out
}

fn metric_help(out: &mut String, name: &str, ty: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {ty}");
}

/// Escapes a Prometheus label value (`\`, `"`, newlines).
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_still_exports_up() {
        let body = render_prometheus(&AppState::new());
        assert!(body.contains("dnscraft_up 1"), "{body}");
        assert!(!body.contains("dnscraft_resolver_resolutions_total"));
    }

    #[test]
    fn escape_label_quotes_and_slashes() {
        assert_eq!(escape_label(r#"a"b\c"#), r#"a\"b\\c"#);
    }
}
