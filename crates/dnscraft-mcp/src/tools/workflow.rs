//! High-level workflow tools for common assistant utterances.
//!
//! `diagnose` accepts an app name, bare domain or pasted URL and returns a
//! single structured answer with a `suggested_next` action. `network_health`
//! and `list_mcp_proposals` collapse the usual multi-tool inventory paths.

use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use serde::Deserialize;
use serde_json::{Value, json};

use super::read::{explain_json, query_entry_json, status_json};
use super::v2_read::{alerts_json, classify_json};
use super::{
    McpServer, backend_call, invalid_input, parse_arguments, require_token, schema, token_from,
};
use crate::dto::{QType, QueryLogSearch, ResolveClientParams};
use crate::error::McpError;
use crate::input::{canonicalize_user_domain, looks_like_domain_or_url};
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, sanitize};

pub const WORKFLOW_TOOL_NAMES: [&str; 3] = ["diagnose", "list_mcp_proposals", "network_health"];

pub fn is_workflow_tool(name: &str) -> bool {
    WORKFLOW_TOOL_NAMES.contains(&name)
}

pub fn tool_definitions() -> Vec<Tool> {
    vec![
        tool(
            "diagnose",
            "Primary entry point when the user names an app (e.g. Instagram) or pastes a website link. Resolves URL/domain/app, explains blocks, shows recent blocks, and returns suggested_next. Prefer this over chaining classify/explain/search yourself.",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "App name, domain, or full URL from the user"
                    },
                    "client": {
                        "type": "string",
                        "description": "Optional client display name or IP"
                    },
                    "profile_id": {
                        "type": "string",
                        "description": "Optional policy profile for explain_block"
                    },
                    "locale": {
                        "type": "string",
                        "description": "Locale for blocked-service names (e.g. de, en)"
                    }
                },
                "required": ["query"]
            }),
        ),
        tool(
            "network_health",
            "One-shot network health: node status, active alerts, and resolver upstream health. Use when the user asks if DNS/the network is healthy.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_mcp_proposals",
            "List pending permanent-exception proposals awaiting owner confirmation in the web UI. Use after propose_exception to check status.",
            json!({ "type": "object" }),
        ),
    ]
}

fn tool(name: &'static str, description: &'static str, input: Value) -> Tool {
    Tool::new(name, description, schema(input)).with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .idempotent(true)
            .open_world(false),
    )
}

pub(crate) fn validate_arguments(name: &str, arguments: Option<JsonObject>) -> bool {
    match name {
        "diagnose" => parse_arguments::<DiagnoseArgs>(arguments).is_ok(),
        "network_health" | "list_mcp_proposals" => parse_arguments::<EmptyArgs>(arguments).is_ok(),
        _ => false,
    }
}

pub(crate) async fn call(
    name: &str,
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    if let Err(error) = require_token(token_from(&context)) {
        return error;
    }
    match name {
        "diagnose" => diagnose(arguments, server, context).await,
        "network_health" => network_health(server, context).await,
        "list_mcp_proposals" => list_mcp_proposals(server, context).await,
        other => tool_error(
            McpError::ToolNotFound { tool: other.into() }.code(),
            json!({ "tool": other }),
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnoseArgs {
    query: String,
    client: Option<String>,
    profile_id: Option<String>,
    locale: Option<String>,
}

async fn diagnose(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let args = match parse_arguments::<DiagnoseArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let query = args.query.trim();
    if query.is_empty() {
        return invalid_input("query must not be empty");
    }
    let query_sanitized = sanitize(query, CAP_DOMAIN.max(CAP_CLIENT_NAME));

    let services = match backend_call(
        "list_blocked_services",
        &context,
        server.backend.list_blocked_services(args.locale.as_deref()),
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return error,
    };

    let client_info = if let Some(raw) = args
        .client
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match backend_call(
            "resolve_client",
            &context,
            server.backend.resolve_client(ResolveClientParams {
                query: raw.to_owned(),
            }),
        )
        .await
        {
            Ok(result) => {
                let client = result.clients.into_iter().next().map(|c| {
                    json!({
                        "id": sanitize(&c.id, CAP_LIST_ID),
                        "display_name": sanitize(&c.display_name, CAP_CLIENT_NAME),
                        "source": sanitize(&c.source, CAP_CLIENT_NAME),
                    })
                });
                if client.is_none() {
                    return tool_error(
                        "control_api.not_found",
                        json!({ "what": "client", "query": sanitize(raw, CAP_CLIENT_NAME) }),
                    );
                }
                client
            }
            Err(error) => return error,
        }
    } else {
        None
    };

    let domain_attempt = if looks_like_domain_or_url(query) {
        canonicalize_user_domain(query).ok()
    } else {
        None
    };

    let service_matches = match_services(&services.items, query, domain_attempt.as_deref());

    if service_matches.len() > 1 && domain_attempt.is_none() {
        return tool_ok(json!({
            "input": {
                "query": query_sanitized,
                "interpreted_as": "ambiguous",
            },
            "candidates": service_matches.iter().map(service_candidate_json).collect::<Vec<_>>(),
            "client": client_info,
            "suggested_next": {
                "action": "ask_user",
                "args_hint": {},
                "reason": "ambiguous_service",
            },
        }));
    }

    let (interpreted_as, domain, service) = if let Some(domain) = domain_attempt {
        let service = service_matches
            .iter()
            .find(|s| s.enabled_in_any)
            .cloned()
            .or_else(|| service_matches.first().cloned());
        ("url_or_domain", Some(domain), service)
    } else if let Some(service) = service_matches.into_iter().next() {
        ("service", None, Some(service))
    } else if let Ok(domain) = canonicalize_user_domain(query) {
        // Single-label names fail write validation but can still be tried as domains
        // when they contain a dot after canonicalize — otherwise treat as unknown.
        ("domain", Some(domain), None)
    } else {
        return tool_ok(json!({
            "input": {
                "query": query_sanitized,
                "interpreted_as": "unknown",
            },
            "client": client_info,
            "suggested_next": {
                "action": "ask_user",
                "args_hint": {},
                "reason": "unresolved_query",
            },
        }));
    };

    let domain_for_ops = domain.clone();

    let classification = if let Some(ref domain) = domain_for_ops {
        match backend_call(
            "classify_domain",
            &context,
            server.backend.classify_domain(domain),
        )
        .await
        {
            Ok(result) => Some(classify_json(&result)),
            Err(error) => return error,
        }
    } else {
        None
    };

    let explain = if let Some(ref domain) = domain_for_ops {
        match backend_call(
            "explain_block",
            &context,
            server
                .backend
                .explain_block(domain, args.profile_id.as_deref(), QType::A),
        )
        .await
        {
            Ok(result) => Some(explain_json(&result)),
            Err(error) => return error,
        }
    } else {
        None
    };

    let search_domain = domain_for_ops.clone();
    let search_substr = if search_domain.is_none() {
        service
            .as_ref()
            .map(|s| s.id.clone())
            .or_else(|| Some(query.to_ascii_lowercase()))
    } else {
        None
    };

    let recent = match backend_call(
        "search_query_log",
        &context,
        server.backend.search_query_log(QueryLogSearch {
            limit: 10,
            offset: 0,
            from: None,
            to: None,
            client_id: client_info
                .as_ref()
                .and_then(|c| c.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            client_name_substr: None,
            domain: search_domain.clone(),
            domain_substr: search_substr,
            protocol: None,
            view_id: None,
            profile_id: args.profile_id.clone(),
            status: None,
            only_blocked: true,
            order_by: "time".into(),
            order: "desc".into(),
        }),
    )
    .await
    {
        Ok(result) => result
            .queries
            .iter()
            .map(query_entry_json)
            .collect::<Vec<_>>(),
        Err(error) => return error,
    };

    // If we only matched a service, pick a concrete domain from recent blocks for next steps.
    let domain = domain.or_else(|| {
        recent
            .first()
            .and_then(|entry| entry.get("query"))
            .and_then(|q| q.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    });

    // Re-run classify/explain if we learned the domain from recent blocks.
    let (classification, explain) = if classification.is_none() {
        if let Some(ref domain) = domain {
            let classification = match backend_call(
                "classify_domain",
                &context,
                server.backend.classify_domain(domain),
            )
            .await
            {
                Ok(result) => Some(classify_json(&result)),
                Err(error) => return error,
            };
            let explain = match backend_call(
                "explain_block",
                &context,
                server
                    .backend
                    .explain_block(domain, args.profile_id.as_deref(), QType::A),
            )
            .await
            {
                Ok(result) => Some(explain_json(&result)),
                Err(error) => return error,
            };
            (classification, explain)
        } else {
            (classification, explain)
        }
    } else {
        (classification, explain)
    };

    let suggested_next = suggested_next(
        service.as_ref(),
        explain.as_ref(),
        classification.as_ref(),
        domain.as_deref(),
        !recent.is_empty(),
    );

    tool_ok(json!({
        "input": {
            "query": query_sanitized,
            "interpreted_as": interpreted_as,
        },
        "domain": domain.as_deref().map(|d| sanitize(d, CAP_DOMAIN)),
        "service": service.as_ref().map(service_candidate_json),
        "classification": classification,
        "explain": explain,
        "recent_blocks": recent,
        "client": client_info,
        "suggested_next": suggested_next,
    }))
}

#[derive(Clone)]
struct ServiceMatch {
    id: String,
    name: String,
    enabled_in_any: bool,
    enabled: Value,
}

fn match_services(items: &[Value], query: &str, domain: Option<&str>) -> Vec<ServiceMatch> {
    let q = query.trim().to_ascii_lowercase();
    let mut exact = Vec::new();
    let mut fuzzy = Vec::new();
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if id.is_empty() {
            continue;
        }
        let id_l = id.to_ascii_lowercase();
        let name_l = name.to_ascii_lowercase();
        let enabled_map = item.get("enabled").cloned().unwrap_or_else(|| json!({}));
        let enabled_in_any = enabled_map
            .as_object()
            .map(|m| m.values().any(|v| v.as_bool() == Some(true)))
            .unwrap_or(false);
        let candidate = ServiceMatch {
            id,
            name,
            enabled_in_any,
            enabled: enabled_map,
        };

        let domain_hit = domain.is_some_and(|d| {
            let d = d.to_ascii_lowercase();
            d == id_l || d.ends_with(&format!(".{id_l}")) || d.split('.').any(|label| label == id_l)
        });

        if id_l == q || name_l == q || domain_hit {
            exact.push(candidate);
        } else if (!q.is_empty() && q.len() >= 3 && (id_l.contains(&q) || name_l.contains(&q)))
            || (q.len() >= 3 && (q.contains(&id_l) || q.contains(&name_l)))
        {
            fuzzy.push(candidate);
        }
    }
    if !exact.is_empty() { exact } else { fuzzy }
}

fn service_candidate_json(service: &ServiceMatch) -> Value {
    json!({
        "id": sanitize(&service.id, CAP_LIST_ID),
        "name": sanitize(&service.name, CAP_CLIENT_NAME),
        "enabled_in_set": service.enabled_in_any,
        "enabled": service.enabled,
    })
}

fn suggested_next(
    service: Option<&ServiceMatch>,
    explain: Option<&Value>,
    classification: Option<&Value>,
    domain: Option<&str>,
    has_recent_blocks: bool,
) -> Value {
    if let Some(service) = service
        && service.enabled_in_any
    {
        return json!({
            "action": "set_blocked_service",
            "args_hint": {
                "service_id": sanitize(&service.id, CAP_LIST_ID),
                "enabled": false,
            },
            "reason": "blocked_service_enabled",
        });
    }

    let verdict = explain
        .and_then(|e| e.get("verdict"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let kind = classification
        .and_then(|c| c.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    if (verdict == "blocked" || has_recent_blocks)
        && let Some(domain) = domain
    {
        let mut args = json!({
            "domain": sanitize(domain, CAP_DOMAIN),
            "duration": "PT15M",
        });
        if kind == "tracking" {
            args["acknowledge_tracking"] = json!(true);
        }
        return json!({
            "action": "allow_temporarily",
            "args_hint": args,
            "reason": if kind == "tracking" {
                "blocked_tracking_needs_consent"
            } else {
                "blocked_by_filter"
            },
        });
    }

    if verdict == "allowed" && !has_recent_blocks {
        return json!({
            "action": "none",
            "args_hint": {},
            "reason": "not_blocked",
        });
    }

    json!({
        "action": "ask_user",
        "args_hint": {},
        "reason": "insufficient_signal",
    })
}

async fn network_health(server: &McpServer, context: RequestContext<RoleServer>) -> CallToolResult {
    let status = backend_call("get_status", &context, server.backend.get_status());
    let alerts = backend_call("list_alerts", &context, server.backend.list_alerts());
    let upstreams = backend_call(
        "list_resolver_upstreams",
        &context,
        server.backend.list_resolver_upstreams(),
    );
    let (status, alerts, upstreams) = tokio::join!(status, alerts, upstreams);
    let status = match status {
        Ok(value) => value,
        Err(error) => return error,
    };
    let alerts = match alerts {
        Ok(value) => value,
        Err(error) => return error,
    };
    let upstreams = match upstreams {
        Ok(value) => value,
        Err(error) => return error,
    };

    let unhealthy_upstreams: Vec<Value> = upstreams
        .items
        .iter()
        .filter(|u| u.state != "ok" && u.state != "healthy" && u.state != "up")
        .map(|u| {
            json!({
                "address": sanitize(&u.address, CAP_DOMAIN),
                "state": sanitize(&u.state, CAP_CLIENT_NAME),
            })
        })
        .collect();

    let issues: Vec<Value> = {
        let mut issues = Vec::new();
        if alerts.active_count > 0 {
            issues.push(json!({ "kind": "alerts", "count": alerts.active_count }));
        }
        for item in &unhealthy_upstreams {
            issues.push(json!({
                "kind": "upstream",
                "address": item.get("address"),
                "state": item.get("state"),
            }));
        }
        for listener in &status.listeners {
            if listener.status != "up" && listener.status != "listening" {
                issues.push(json!({
                    "kind": "listener",
                    "id": sanitize(&listener.id, CAP_LIST_ID),
                    "status": sanitize(&listener.status, CAP_CLIENT_NAME),
                }));
            }
        }
        issues
    };

    tool_ok(json!({
        "summary": {
            "ok": issues.is_empty(),
            "issue_count": issues.len(),
        },
        "status": status_json(&status),
        "alerts": alerts_json(alerts),
        "upstreams": {
            "items": upstreams.items.iter().map(|u| json!({
                "address": sanitize(&u.address, CAP_DOMAIN),
                "state": sanitize(&u.state, CAP_CLIENT_NAME),
            })).collect::<Vec<_>>(),
        },
        "issues": issues,
    }))
}

async fn list_mcp_proposals(
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    match backend_call(
        "list_mcp_proposals",
        &context,
        server.backend.list_mcp_proposals(),
    )
    .await
    {
        Ok(result) => tool_ok(json!({
            "proposals": result.proposals.into_iter().map(sanitize_proposal).collect::<Vec<_>>(),
        })),
        Err(error) => error,
    }
}

fn sanitize_proposal(mut proposal: Value) -> Value {
    if let Some(obj) = proposal.as_object_mut() {
        for key in ["id", "filter_set_id", "token_id"] {
            if let Some(Value::String(value)) = obj.get(key) {
                let cleaned = sanitize(value, CAP_LIST_ID);
                obj.insert(key.to_owned(), Value::String(cleaned));
            }
        }
        if let Some(Value::String(value)) = obj.get("domain") {
            let cleaned = sanitize(value, CAP_DOMAIN);
            obj.insert("domain".into(), Value::String(cleaned));
        }
        if let Some(Value::String(value)) = obj.get("reason") {
            let cleaned = sanitize(value, crate::sanitize::CAP_REASON);
            obj.insert("reason".into(), Value::String(cleaned));
        }
        if let Some(Value::String(value)) = obj.get("rule_text") {
            let cleaned = sanitize(value, crate::sanitize::CAP_RULE_TEXT);
            obj.insert("rule_text".into(), Value::String(cleaned));
        }
    }
    proposal
}
