//! `GET /api/v1/alerts` (WP1): the active alerts, assembled from readiness,
//! TLS, resolver, filter lists, cluster, listeners, clients, query log,
//! backups and the update-check cache. Each item names its module and a
//! stable id; the web UI owns the wording.

use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use dnscraft_cluster::{ClusterNode, Role};
use dnscraft_resolver::{PrimingStatus, UpstreamState};

use crate::api::response::success;
use crate::cloudflare_secrets::dyndns_enabled_for;
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::system::{last_backup, unix_now, update_check_enabled};
use crate::tls::{TlsMode, TlsStatus};

/// A registered sub-node is offline when its last authenticated connection
/// (or its join time, if it never connected) is older than this (WP1).
const NODE_OFFLINE_AFTER_SECS: i64 = 300;

/// Heartbeat warning codes that map 1:1 onto alert ids.
const HEARTBEAT_ALERT_IDS: &[&str] = &[
    "cluster.clock_skew",
    "cluster.master_conflict",
    "cluster.config.stale",
    "cluster.offline_write_queue_full",
];

/// `GET /api/v1/alerts` — viewer and admin. An empty `items` list means no
/// active alert.
pub(crate) async fn list_alerts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let items = collect_alerts(&state).await;
    Ok(success(json!({
        "active_count": items.len(),
        "items": items,
    })))
}

/// The active alert items. Shared by the route and the webhook dispatcher (WX7).
pub(crate) async fn collect_alerts(state: &AppState) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();

    push_readiness_alerts(state, &mut items);
    push_listener_alerts(state, &mut items);
    push_resolver_alerts(state, &mut items);
    push_tls_alerts(state, &mut items).await;
    push_filter_alerts(state, &mut items);
    push_cluster_alerts(state, &mut items).await;
    push_clients_alerts(state, &mut items);
    push_querylog_alerts(state, &mut items);
    push_backup_alerts(state, &mut items).await;
    push_update_alerts(state, &mut items).await;

    items
}

fn push_readiness_alerts(state: &AppState, items: &mut Vec<Value>) {
    let modules = state.readiness().not_ready_modules();
    if modules.is_empty() {
        return;
    }
    items.push(alert(
        "system.not_ready",
        "critical",
        "system",
        json!({ "modules": modules }),
        "/dashboard",
    ));
}

fn push_listener_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(provider) = state.listeners_status() else {
        return;
    };
    for listener in provider.listeners_status().listeners {
        let Some(error) = listener.error.as_ref() else {
            continue;
        };
        items.push(alert(
            "listeners.bind_failed",
            "critical",
            "listeners",
            json!({
                "listener_id": listener.id.as_str(),
                "code": error.code(),
            }),
            "/listeners",
        ));
    }
}

fn push_resolver_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(resolver) = state.resolver() else {
        return;
    };
    push_resolver_health_alerts(resolver.priming_status(), &resolver.upstreams(), items);
}

/// Maps priming + upstream health into alert items (unit-tested without a live resolver).
fn push_resolver_health_alerts(
    priming: PrimingStatus,
    upstreams: &[dnscraft_resolver::UpstreamHealth],
    items: &mut Vec<Value>,
) {
    if matches!(priming, PrimingStatus::FellBack) {
        items.push(alert(
            "resolver.priming.fallback",
            "warning",
            "resolver",
            json!({}),
            "/dashboard",
        ));
    }
    for upstream in upstreams {
        let (id, severity) = match upstream.state {
            UpstreamState::Down => ("resolver.upstream.down", "critical"),
            UpstreamState::Degraded => ("resolver.upstream.degraded", "warning"),
            UpstreamState::Up | UpstreamState::Unknown => continue,
        };
        items.push(alert(
            id,
            severity,
            "resolver",
            json!({
                "name": upstream.name,
                "kind": upstream.kind,
                "code": upstream.last_error,
            }),
            "/dashboard",
        ));
    }
}

async fn push_tls_alerts(state: &AppState, items: &mut Vec<Value>) {
    let tls = state.tls_status_async().await;
    if let Some(tls) = tls.as_ref() {
        push_tls_status_alerts(tls, items);
    }

    if let Some(admin) = state.tls_admin() {
        if let Ok(inventory) = admin.record_inventory().await {
            let conflicts: Vec<Value> = inventory
                .get("records")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|record| record.get("conflict").and_then(Value::as_bool) == Some(true))
                .map(|record| {
                    json!({
                        "name": record.get("name"),
                        "record_type": record.get("record_type"),
                    })
                })
                .collect();
            if !conflicts.is_empty() {
                items.push(alert(
                    "tls.dns.conflict",
                    "warning",
                    "tls",
                    json!({ "count": conflicts.len(), "records": conflicts }),
                    "/tls",
                ));
            }
        }

        let needs_token = tls_needs_cloudflare_token(state).await;
        if needs_token {
            let has_token = match admin.has_cloudflare_token().await {
                Ok(value) => value
                    .get("has_cloudflare_token")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                Err(_) => false,
            };
            if !has_token {
                items.push(alert(
                    "tls.secret.missing",
                    "warning",
                    "tls",
                    json!({}),
                    "/tls",
                ));
            }
        }
    }
}

fn push_tls_status_alerts(tls: &TlsStatus, items: &mut Vec<Value>) {
    if tls.mode == TlsMode::SelfSigned {
        items.push(alert(
            "tls.bootstrap.self_signed",
            "warning",
            "tls",
            json!({}),
            "/tls",
        ));
    }
    if tls.store.as_ref().is_some_and(|store| store.corrupt) {
        items.push(alert(
            "tls.store.corrupt",
            "critical",
            "tls",
            json!({}),
            "/tls",
        ));
    }

    let mut cert_critical = false;
    if tls.revoked {
        cert_critical = true;
        items.push(alert(
            "tls.cert.revoked",
            "critical",
            "tls",
            json!({}),
            "/tls",
        ));
    } else if tls.cert_expired {
        cert_critical = true;
        items.push(alert(
            "tls.cert.expired",
            "critical",
            "tls",
            json!({}),
            "/tls",
        ));
    } else if tls.cert_expiring {
        items.push(alert(
            "tls.cert.expiring",
            "warning",
            "tls",
            json!({ "days_to_expiry": tls.days_to_expiry }),
            "/tls",
        ));
    }
    if tls.dyndns_stale {
        items.push(alert(
            "tls.dyndns.stale",
            "warning",
            "tls",
            json!({}),
            "/tls",
        ));
    }
    if let Some(code) = tls.last_error.as_ref()
        && !cert_critical
    {
        items.push(alert(
            "tls.engine.error",
            "warning",
            "tls",
            json!({ "code": code }),
            "/tls",
        ));
    }
}

async fn tls_needs_cloudflare_token(state: &AppState) -> bool {
    let Some(service) = state.config_service() else {
        return false;
    };
    let Ok((_, Some(snapshot))) = service.current().await else {
        return false;
    };
    if dyndns_enabled_for(&snapshot, state.node_id()) {
        return true;
    }
    snapshot
        .pointer("/tls/dns_provider/zones")
        .and_then(Value::as_array)
        .is_some_and(|zones| !zones.is_empty())
}

fn push_filter_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(filter) = state.filter_engine() else {
        return;
    };
    for list in filter.list_status() {
        if let Some(code) = list.error_code {
            items.push(alert(
                "filtering.list.update_failed",
                "warning",
                "filtering",
                json!({ "list_id": list.id.as_str(), "code": code }),
                "/filter-lists",
            ));
        }
    }
}

async fn push_cluster_alerts(state: &AppState, items: &mut Vec<Value>) {
    let cluster = state
        .cluster_status()
        .and_then(|provider| provider.cluster_status());

    if let Some(cluster) = cluster.as_ref() {
        if cluster.role == "sub_node" && !cluster.master_reachable {
            items.push(alert(
                "cluster.master.unreachable",
                "warning",
                "cluster",
                json!({}),
                "/cluster",
            ));
        }
        if cluster.role == "master" && cluster.degraded_nodes > 0 {
            items.push(alert(
                "cluster.sync.degraded",
                "warning",
                "cluster",
                json!({ "count": cluster.degraded_nodes }),
                "/cluster",
            ));
        }
        if cluster.role == "sub_node" && cluster.lag > 0 {
            items.push(alert(
                "cluster.config.lag",
                "warning",
                "cluster",
                json!({ "lag": cluster.lag }),
                "/cluster",
            ));
        }
        if let Some(error) = cluster.last_apply_error.as_ref() {
            items.push(alert(
                "cluster.apply_failed",
                "warning",
                "cluster",
                json!({ "error": error }),
                "/cluster",
            ));
        }
        for warning in &cluster.warnings {
            if HEARTBEAT_ALERT_IDS.contains(&warning.code.as_str()) {
                items.push(alert(
                    &warning.code,
                    "warning",
                    "cluster",
                    warning.params.clone().unwrap_or(json!({})),
                    "/cluster",
                ));
            }
        }
    }

    if state.cluster_role() == Some(Role::Master)
        && let Some(store) = state.cluster_store()
        && let Ok(nodes) = store.list_nodes().await
    {
        items.extend(offline_node_alerts(&nodes, unix_now(state)));
        let connected: std::collections::HashSet<String> = state
            .cluster_broadcast()
            .map(|broadcast| broadcast.connected_node_ids().into_iter().collect())
            .unwrap_or_default();
        for node in &nodes {
            if node.revoked || connected.contains(&node.node_id) {
                continue;
            }
            // Live disconnect is finer-grained than the 5-minute offline alert.
            let seen = node.last_seen.unwrap_or(node.joined_at);
            if unix_now(state).saturating_sub(seen) <= NODE_OFFLINE_AFTER_SECS {
                items.push(alert(
                    "cluster.node.disconnected",
                    "warning",
                    "cluster",
                    json!({ "node_id": node.node_id }),
                    "/cluster",
                ));
            }
        }
    }
}

fn push_clients_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(directory) = state.client_directory() else {
        return;
    };
    let health = directory.health();
    if let Some(code) = health.last_error {
        items.push(alert(
            "clients.unifi.sync_failed",
            "warning",
            "clients",
            json!({ "code": code }),
            "/clients",
        ));
    }
    if health.ip_conflicts > 0 {
        items.push(alert(
            "clients.unifi.ip_conflicts",
            "warning",
            "clients",
            json!({ "count": health.ip_conflicts }),
            "/clients",
        ));
    }
}

fn push_querylog_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(log) = state.query_log() else {
        return;
    };
    let dropped = log.sink_dropped();
    if dropped > 0 {
        items.push(alert(
            "querylog.dropped",
            "warning",
            "querylog",
            json!({ "count": dropped }),
            "/query-log",
        ));
    }
}

async fn push_backup_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(db) = state.db() else {
        return;
    };
    let Ok(Some(last)) = last_backup(db).await else {
        return;
    };
    if last.get("result").and_then(Value::as_str) == Some("error") {
        items.push(alert(
            "system.backup.failed",
            "warning",
            "system",
            json!({ "code": last.get("code") }),
            "/settings/config",
        ));
    }
}

async fn push_update_alerts(state: &AppState, items: &mut Vec<Value>) {
    let Some(service) = state.config_service() else {
        return;
    };
    let Ok((_, Some(snapshot))) = service.current().await else {
        return;
    };
    if !update_check_enabled(&snapshot) {
        return;
    }
    let cache = state.update_cache().lock().await;
    if let Some((_, Err(code))) = cache.as_ref() {
        items.push(alert(
            "system.update.unreachable",
            "warning",
            "system",
            json!({ "code": *code }),
            "/settings",
        ));
    }
}

/// One alert item in the documented shape.
fn alert(id: &str, severity: &str, module: &str, params: Value, target_route: &str) -> Value {
    json!({
        "id": id,
        "severity": severity,
        "module": module,
        "params": params,
        "target_route": target_route,
    })
}

/// Alerts for registered, non-revoked sub-nodes that have gone quiet (WP1).
fn offline_node_alerts(nodes: &[ClusterNode], now: i64) -> Vec<Value> {
    nodes
        .iter()
        .filter(|node| !node.revoked)
        .filter(|node| {
            let seen = node.last_seen.unwrap_or(node.joined_at);
            now.saturating_sub(seen) > NODE_OFFLINE_AFTER_SECS
        })
        .map(|node| {
            alert(
                "cluster.node.offline",
                "warning",
                "cluster",
                json!({ "node_id": node.node_id, "last_seen": node.last_seen }),
                "/cluster",
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn node(id: &str, last_seen: Option<i64>, revoked: bool) -> ClusterNode {
        ClusterNode {
            node_id: id.to_owned(),
            fingerprint: "00".to_owned(),
            joined_at: 1_000,
            last_seen,
            applied_config_version: None,
            revoked,
            remote_addr: None,
            software_version: None,
        }
    }

    #[test]
    fn only_quiet_active_nodes_raise_an_offline_alert() {
        let now = 10_000;
        let nodes = [
            node("fresh", Some(now - 10), false),
            node("quiet", Some(now - 900), false),
            node("never-seen", None, false),
            node("revoked", Some(now - 900), true),
        ];
        let alerts = offline_node_alerts(&nodes, now);
        let ids: Vec<&str> = alerts
            .iter()
            .map(|alert| alert["params"]["node_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["quiet", "never-seen"]);
        assert_eq!(alerts[0]["id"], "cluster.node.offline");
        assert_eq!(alerts[0]["target_route"], "/cluster");
    }

    fn upstream(name: &str, state: UpstreamState) -> dnscraft_resolver::UpstreamHealth {
        dnscraft_resolver::UpstreamHealth {
            name: name.to_owned(),
            kind: "forward_target",
            zone: Some(".".to_owned()),
            protocol: "udp",
            state,
            samples: 20,
            rtt_p50_ms: None,
            rtt_p95_ms: None,
            success_rate: Some(0.1),
            last_error: Some("upstream.timeout"),
            last_checked: None,
        }
    }

    #[test]
    fn resolver_health_emits_priming_and_upstream_alerts() {
        let mut items = Vec::new();
        push_resolver_health_alerts(
            PrimingStatus::FellBack,
            &[
                upstream("1.1.1.1", UpstreamState::Down),
                upstream("9.9.9.9", UpstreamState::Degraded),
                upstream("8.8.8.8", UpstreamState::Up),
                upstream("new", UpstreamState::Unknown),
            ],
            &mut items,
        );
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [
                "resolver.priming.fallback",
                "resolver.upstream.down",
                "resolver.upstream.degraded",
            ]
        );
        assert_eq!(items[1]["severity"], "critical");
        assert_eq!(items[1]["params"]["name"], "1.1.1.1");
        assert_eq!(items[2]["severity"], "warning");
    }

    #[test]
    fn tls_engine_error_is_suppressed_when_a_cert_is_already_critical() {
        let mut tls = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
        tls.revoked = true;
        tls.last_error = Some("tls.acme.order_failed".to_owned());
        let mut items = Vec::new();
        push_tls_status_alerts(&tls, &mut items);
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["tls.cert.revoked"]);
    }

    #[test]
    fn tls_engine_error_and_corrupt_store_surface_when_alone() {
        let mut tls = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
        tls.last_error = Some("tls.acme.order_failed".to_owned());
        tls.store = Some(crate::tls::StoreHealth {
            path: "/tmp/store".to_owned(),
            writable: false,
            last_write: None,
            corrupt: true,
        });
        let mut items = Vec::new();
        push_tls_status_alerts(&tls, &mut items);
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"tls.store.corrupt"));
        assert!(ids.contains(&"tls.engine.error"));
        assert_eq!(
            items
                .iter()
                .find(|item| item["id"] == "tls.engine.error")
                .unwrap()["params"]["code"],
            "tls.acme.order_failed"
        );
    }
}
