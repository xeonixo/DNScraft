//! MCP v2 surface: classify, clarify, new writes, prompts and resources.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use dnscraft_mcp::{
    BackendError, CancelTempAllowResult, ClassifyDomainResult, ClientInfo, ListAlertsResult,
    McpConfig, TempAllowResult,
};
use serde_json::{Value, json};
use support::harness::{self, TestServer};

fn read_config() -> McpConfig {
    support::high_rate_config(McpConfig::default())
}

fn write_config() -> McpConfig {
    support::high_rate_config(McpConfig {
        write_tools_enabled: true,
        ..McpConfig::default()
    })
}

async fn spawn_read() -> TestServer {
    harness::spawn_with(read_config(), support::read_token()).await
}

async fn spawn_write() -> TestServer {
    harness::spawn_with(write_config(), support::write_token()).await
}

async fn call(server: &TestServer, name: &str, arguments: Value) -> Value {
    let client = reqwest::Client::new();
    let (status, body) = harness::tool_call(&client, server, name, arguments.clone()).await;
    assert_eq!(status, 200, "{name} {arguments}: {body}");
    body
}

#[tokio::test]
async fn classify_domain_returns_tracker_kind() {
    let server = spawn_read().await;
    server.backend.set_classify(ClassifyDomainResult {
        domain: "ads.example.com".into(),
        kind: "tracking".into(),
        category: Some("advertising".into()),
        name: Some("Example Ads".into()),
        source: "trackers_db".into(),
    });
    let body = call(
        &server,
        "classify_domain",
        json!({ "domain": "ads.example.com" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let out = harness::tool_output(&body);
    assert_eq!(out["kind"], "tracking");
    assert_eq!(out["category"], "advertising");
    assert_eq!(out["source"], "trackers_db");
}

#[tokio::test]
async fn list_alerts_returns_active_items() {
    let server = spawn_read().await;
    server.backend.set_alerts(ListAlertsResult {
        active_count: 1,
        items: vec![json!({
            "id": "system.not_ready",
            "severity": "critical",
            "module": "system",
        })],
    });
    let body = call(&server, "list_alerts", json!({})).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let out = harness::tool_output(&body);
    assert_eq!(out["active_count"], 1);
    assert_eq!(out["items"][0]["id"], "system.not_ready");
}

#[tokio::test]
async fn resolve_client_returns_single_match() {
    let server = spawn_read().await;
    server.backend.set_clients(vec![ClientInfo {
        id: "phone".into(),
        display_name: "Malte Phone".into(),
        source: "unifi".into(),
        addresses: vec!["192.0.2.10".into()],
        ..Default::default()
    }]);
    let body = call(&server, "resolve_client", json!({ "query": "Malte Phone" })).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let out = harness::tool_output(&body);
    assert_eq!(out["clients"].as_array().unwrap().len(), 1);
    assert_eq!(out["clients"][0]["id"], "phone");
}

#[tokio::test]
async fn resolve_client_reports_ambiguous_matches() {
    let server = spawn_read().await;
    server.backend.set_clients(vec![
        ClientInfo {
            id: "a".into(),
            display_name: "Living Room".into(),
            source: "unifi".into(),
            addresses: vec!["192.0.2.1".into()],
            ..Default::default()
        },
        ClientInfo {
            id: "b".into(),
            display_name: "Living Room".into(),
            source: "manual".into(),
            addresses: vec!["192.0.2.2".into()],
            ..Default::default()
        },
    ]);
    let body = call(&server, "resolve_client", json!({ "query": "Living Room" })).await;
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(harness::error_code(&body), "mcp.ambiguous_client");
    assert_eq!(
        body["result"]["structuredContent"]["error"]["params"]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn cancel_temporary_allow_succeeds_and_audits() {
    let server = spawn_write().await;
    server.backend.set_cancel(Ok(CancelTempAllowResult {
        removed: true,
        filter_set_id: "kids".into(),
    }));
    let body = call(
        &server,
        "cancel_temporary_allow",
        json!({ "domain": "blocked.example", "filter_set_id": "kids" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(server.backend.cancel_calls(), 1);
    let out = harness::tool_output(&body);
    assert_eq!(out["removed"], true);
    assert_eq!(out["filter_set_id"], "kids");
    let audits = server.backend.audits();
    assert!(
        audits
            .iter()
            .any(|entry| entry.action == "mcp.cancel_temporary_allow"),
        "{audits:?}"
    );
}

#[tokio::test]
async fn cancel_temporary_allow_forwards_needs_clarification() {
    let server = spawn_write().await;
    server.backend.set_cancel(Err(BackendError::Coded {
        code: "mcp.needs_clarification".into(),
        params: Some(json!({
            "reason": "multiple filter sets; specify filter_set_id",
            "candidates": [
                { "filter_set_id": "default" },
                { "filter_set_id": "kids" }
            ],
        })),
    }));
    let body = call(
        &server,
        "cancel_temporary_allow",
        json!({ "domain": "blocked.example" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(harness::error_code(&body), "mcp.needs_clarification");
    assert_eq!(
        body["result"]["structuredContent"]["error"]["params"]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn flush_cache_full_and_domain_scoped() {
    let server = spawn_write().await;
    let body = call(&server, "flush_cache", json!({})).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(harness::tool_output(&body)["flushed"], true);
    assert_eq!(server.backend.flush_calls(), 1);

    let body = call(
        &server,
        "flush_cache",
        json!({ "domain": "cdn.example.com" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(harness::tool_output(&body)["domain"], "cdn.example.com");
    assert_eq!(server.backend.flush_calls(), 2);
}

#[tokio::test]
async fn set_blocked_service_toggles_and_records_params() {
    let server = spawn_write().await;
    let body = call(
        &server,
        "set_blocked_service",
        json!({
            "service_id": "youtube",
            "enabled": true,
            "filter_set_id": "kids"
        }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let params = server.backend.last_blocked_service().unwrap();
    assert_eq!(params.service_id, "youtube");
    assert!(params.enabled);
    assert_eq!(params.filter_set_id.as_deref(), Some("kids"));
}

#[tokio::test]
async fn propose_exception_refuses_tracking_without_acknowledge() {
    let server = spawn_write().await;
    server.backend.set_classify(ClassifyDomainResult {
        domain: "tracker.example".into(),
        kind: "tracking".into(),
        category: Some("site_analytics".into()),
        name: Some("Analytics Co".into()),
        source: "trackers_db".into(),
    });
    let body = call(
        &server,
        "propose_exception",
        json!({ "domain": "tracker.example", "reason": "site broken" }),
    )
    .await;
    assert_eq!(harness::error_code(&body), "mcp.tracking_domain_refused");
}

#[tokio::test]
async fn allow_temporarily_allows_functional_without_acknowledge() {
    let server = spawn_write().await;
    server.backend.set_classify(ClassifyDomainResult {
        domain: "cdn.example".into(),
        kind: "functional".into(),
        category: Some("cdn".into()),
        name: Some("CDN".into()),
        source: "trackers_db".into(),
    });
    server.backend.set_allow(Ok(TempAllowResult {
        created_at: "2026-11-02T12:00:00Z".into(),
        expires_at: "2026-11-02T12:05:00Z".into(),
        filter_set_id: "default".into(),
    }));
    let body = call(
        &server,
        "allow_temporarily",
        json!({ "domain": "cdn.example", "duration": "PT5M" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(server.backend.allow_calls(), 1);
}

#[tokio::test]
async fn prompts_list_and_get_expose_clarify_workflows() {
    let server = spawn_read().await;
    let client = reqwest::Client::new();
    let (status, body) = harness::rpc(&client, &server, "prompts/list", None, json!({})).await;
    assert_eq!(status, 200, "{body}");
    let prompts = body["result"]["prompts"].as_array().expect("prompts");
    let names: Vec<&str> = prompts
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"diagnose_block"));
    assert!(names.contains(&"network_health_check"));
    assert!(names.contains(&"temporary_access"));

    let (status, body) = harness::rpc(
        &client,
        &server,
        "prompts/get",
        Some("temporary_access"),
        json!({ "name": "temporary_access" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let blob = body.to_string();
    assert!(
        blob.contains("classify_domain") && blob.contains("acknowledge_tracking"),
        "{body}"
    );
}

#[tokio::test]
async fn resources_list_and_read_safe_catalogs() {
    let server = spawn_read().await;
    server.backend.set_alerts(ListAlertsResult {
        active_count: 0,
        items: vec![],
    });
    let client = reqwest::Client::new();
    let (status, body) = harness::rpc(&client, &server, "resources/list", None, json!({})).await;
    assert_eq!(status, 200, "{body}");
    let uris: Vec<&str> = body["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"dnscraft://status"));
    assert!(uris.contains(&"dnscraft://alerts"));
    assert!(uris.contains(&"dnscraft://filter-lists"));
    assert!(uris.contains(&"dnscraft://policy/map"));

    let (status, body) = harness::rpc(
        &client,
        &server,
        "resources/read",
        Some("dnscraft://alerts"),
        json!({ "uri": "dnscraft://alerts" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let text = body["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource text");
    let payload: Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["active_count"], 0);

    let (status, body) = harness::rpc(
        &client,
        &server,
        "resources/read",
        Some("dnscraft://query-log"),
        json!({ "uri": "dnscraft://query-log" }),
    )
    .await;
    // Unknown resource is a JSON-RPC/params error, not tool content.
    assert!(
        status == 200 && body["error"].is_object()
            || body["result"]["isError"] == true
            || body["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("unknown")),
        "query-log must not be a resource: {body}"
    );
}

#[tokio::test]
async fn v2_read_tools_accept_empty_inventory_calls() {
    let server = spawn_read().await;
    for name in [
        "list_filter_lists",
        "list_filter_sets",
        "list_policy_views",
        "list_resolver_upstreams",
        "list_domain_zones",
        "list_listeners",
        "list_policy_records",
        "list_blocked_services",
    ] {
        let body = call(&server, name, json!({})).await;
        assert_eq!(body["result"]["isError"], false, "{name}: {body}");
    }
}

#[tokio::test]
async fn zone_record_writes_require_write_scope_and_gate() {
    let read_only = harness::spawn_with(write_config(), support::read_token()).await;
    let body = call(
        &read_only,
        "create_zone_record",
        json!({
            "zone_id": "zone-1",
            "name": "www",
            "type": "A",
            "content": "192.0.2.1"
        }),
    )
    .await;
    assert_eq!(
        harness::error_code(&body),
        "control_api.auth.insufficient_scope"
    );

    let gated = harness::spawn_with(read_config(), support::write_token()).await;
    let body = call(&gated, "flush_cache", json!({})).await;
    assert_eq!(harness::error_code(&body), "mcp.write_tools_disabled");
}
