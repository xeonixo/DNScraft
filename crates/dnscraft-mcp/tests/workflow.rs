//! Workflow tools: diagnose, network_health, list_mcp_proposals.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use dnscraft_mcp::McpConfig;
use dnscraft_mcp::dto::{
    ClassifyDomainResult, ClientInfo, ExplainBlockResult, ExplainReason, ListAlertsResult,
    ListBlockedServicesResult, ListMcpProposalsResult, QueryClient, QueryLogEntry, QueryName,
    QueryTimings,
};
use serde_json::{Value, json};
use support::harness::{self, TestServer};
use support::{high_rate_config, write_token};

fn write_config() -> McpConfig {
    high_rate_config(McpConfig {
        write_tools_enabled: true,
        ..McpConfig::default()
    })
}

async fn spawn() -> TestServer {
    harness::spawn_with(write_config(), write_token()).await
}

async fn call(server: &TestServer, name: &str, arguments: Value) -> Value {
    let client = reqwest::Client::new();
    let (status, body) = harness::tool_call(&client, server, name, arguments.clone()).await;
    assert_eq!(status, 200, "{name} {arguments}: {body}");
    body
}

#[tokio::test]
async fn diagnose_accepts_url_and_suggests_temp_allow() {
    let server = spawn().await;
    server.backend.set_classify(ClassifyDomainResult {
        domain: "www.instagram.com".into(),
        kind: "functional".into(),
        source: "trackers_db".into(),
        ..Default::default()
    });
    server.backend.set_explain(Ok(ExplainBlockResult {
        domain: "www.instagram.com".into(),
        profile_id: "default".into(),
        filter_set_id: "default".into(),
        verdict: "blocked".into(),
        reason: Some(ExplainReason {
            rule_text: "||instagram.com^".into(),
            source: "list:social".into(),
            important: false,
            block_mode: "nxdomain".into(),
        }),
    }));
    server.backend.set_query_log(vec![QueryLogEntry {
        id: "q1".into(),
        time: "2026-11-24T12:00:00Z".into(),
        client: QueryClient {
            id: "c1".into(),
            display_name: "phone".into(),
            source: "unifi".into(),
        },
        query: QueryName {
            name: "www.instagram.com".into(),
            ..Default::default()
        },
        profile_id: "default".into(),
        answer_source: "filter".into(),
        rcode: "NXDOMAIN".into(),
        timings: QueryTimings { total_us: 100 },
        ..Default::default()
    }]);

    let body = call(
        &server,
        "diagnose",
        json!({ "query": "https://www.instagram.com/p/abc" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["input"]["interpreted_as"], "url_or_domain");
    assert_eq!(structured["domain"], "www.instagram.com");
    assert_eq!(structured["explain"]["verdict"], "blocked");
    assert_eq!(structured["suggested_next"]["action"], "allow_temporarily");
    assert_eq!(
        structured["suggested_next"]["args_hint"]["filter_set_id"],
        "default",
        "diagnose must pass explain's filter_set_id so allow_temporarily does not need clarification"
    );
    assert!(
        structured.is_object(),
        "success should carry structuredContent"
    );
}

#[tokio::test]
async fn diagnose_matches_app_name_to_blocked_service() {
    let server = spawn().await;
    server
        .backend
        .set_blocked_services(ListBlockedServicesResult {
            available: true,
            items: vec![json!({
                "id": "instagram",
                "name": "Instagram",
                "enabled": { "default": true }
            })],
        });

    let body = call(&server, "diagnose", json!({ "query": "Instagram" })).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["input"]["interpreted_as"], "service");
    assert_eq!(structured["service"]["id"], "instagram");
    assert_eq!(structured["service"]["enabled_in_set"], true);
    assert_eq!(
        structured["suggested_next"]["action"],
        "set_blocked_service"
    );
    assert_eq!(structured["suggested_next"]["args_hint"]["enabled"], false);
}

#[tokio::test]
async fn diagnose_ambiguous_services_ask_user() {
    let server = spawn().await;
    server
        .backend
        .set_blocked_services(ListBlockedServicesResult {
            available: true,
            items: vec![
                json!({ "id": "chat", "name": "Acme Chat", "enabled": { "default": false } }),
                json!({ "id": "chatapp", "name": "Chat", "enabled": { "default": false } }),
            ],
        });
    // Exact hits: id `chat` and name `Chat` both equal query "chat".
    let body = call(&server, "diagnose", json!({ "query": "chat" })).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["input"]["interpreted_as"], "ambiguous");
    assert_eq!(structured["suggested_next"]["action"], "ask_user");
    assert!(structured["candidates"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn network_health_aggregates_and_flags_issues() {
    let server = spawn().await;
    server.backend.set_alerts(ListAlertsResult {
        active_count: 1,
        items: vec![json!({ "id": "tls-expiring" })],
    });
    let body = call(&server, "network_health", json!({})).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["summary"]["ok"], false);
    assert_eq!(structured["alerts"]["active_count"], 1);
    assert!(structured["status"].is_object());
}

#[tokio::test]
async fn list_mcp_proposals_returns_pending() {
    let server = spawn().await;
    server.backend.set_proposals(ListMcpProposalsResult {
        proposals: vec![json!({
            "id": "p1",
            "filter_set_id": "default",
            "domain": "needed.example",
            "include_subdomains": false,
            "reason": "work",
        })],
    });
    let body = call(&server, "list_mcp_proposals", json!({})).await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(
        body["result"]["structuredContent"]["proposals"][0]["id"],
        "p1"
    );
}

#[tokio::test]
async fn allow_temporarily_accepts_url() {
    let server = spawn().await;
    server.backend.set_classify(ClassifyDomainResult {
        domain: "ads.example.com".into(),
        kind: "functional".into(),
        source: "none".into(),
        ..Default::default()
    });
    let body = call(
        &server,
        "allow_temporarily",
        json!({
            "domain": "https://ads.example.com/track?x=1",
            "duration": "PT5M"
        }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    let last = server.backend.last_allow().expect("allow called");
    assert_eq!(last.domain, "ads.example.com");
}

#[tokio::test]
async fn diagnose_with_client_resolves_device() {
    let server = spawn().await;
    server.backend.set_clients(vec![ClientInfo {
        id: "ipad".into(),
        display_name: "Kids iPad".into(),
        source: "unifi".into(),
        addresses: vec![],
        macs: vec![],
        vlan: None,
        local_domain: None,
    }]);
    server
        .backend
        .set_blocked_services(ListBlockedServicesResult {
            available: true,
            items: vec![json!({
                "id": "tiktok",
                "name": "TikTok",
                "enabled": { "default": true }
            })],
        });
    let body = call(
        &server,
        "diagnose",
        json!({ "query": "TikTok", "client": "Kids iPad" }),
    )
    .await;
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(body["result"]["structuredContent"]["client"]["id"], "ipad");
}
