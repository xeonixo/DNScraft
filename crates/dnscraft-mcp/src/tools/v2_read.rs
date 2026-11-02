//! MCP v2 read tools (alerts, inventory, classification, stats extras).

use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    McpServer, backend_call, invalid_input, parse_arguments, require_token, schema, token_from,
};
use crate::dto::{
    ClassifyDomainResult, DomainStatsParams, ListAlertsResult, ResolveClientParams,
    StatsTimeseriesParams,
};
use crate::error::McpError;
use crate::protected::canonicalize;
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, sanitize};

pub const V2_READ_TOOL_NAMES: [&str; 14] = [
    "classify_domain",
    "list_alerts",
    "list_filter_lists",
    "list_filter_sets",
    "list_policy_views",
    "list_resolver_upstreams",
    "list_blocked_services",
    "list_domain_zones",
    "list_zone_records",
    "list_listeners",
    "list_policy_records",
    "get_domain_stats",
    "get_stats_timeseries",
    "resolve_client",
];

pub fn is_v2_read_tool(name: &str) -> bool {
    V2_READ_TOOL_NAMES.contains(&name)
}

pub fn tool_definitions() -> Vec<Tool> {
    vec![
        tool(
            "classify_domain",
            "Classify a domain using the tracker database (tracking vs functional). Call before allow_temporarily or propose_exception.",
            json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Canonical domain" }
                },
                "required": ["domain"]
            }),
        ),
        tool(
            "list_alerts",
            "List active operational alerts (TLS, resolver, cluster, listeners, etc.).",
            json!({ "type": "object" }),
        ),
        tool(
            "list_filter_lists",
            "List configured filter lists and their update status.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_filter_sets",
            "List filter sets defined in configuration.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_policy_views",
            "List policy views and their profile bindings.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_resolver_upstreams",
            "List configured resolver upstreams and health state.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_blocked_services",
            "List the blocked-services catalog and which are enabled per filter set.",
            json!({
                "type": "object",
                "properties": {
                    "locale": { "type": "string", "description": "Locale for labels (optional)" }
                }
            }),
        ),
        tool(
            "list_domain_zones",
            "List DNS zones attached for public records management.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_zone_records",
            "List DNS records in one attached zone.",
            json!({
                "type": "object",
                "properties": {
                    "zone_id": { "type": "string" }
                },
                "required": ["zone_id"]
            }),
        ),
        tool(
            "list_listeners",
            "List DNS listener definitions from configuration.",
            json!({ "type": "object" }),
        ),
        tool(
            "list_policy_records",
            "List static local DNS records from policy configuration.",
            json!({ "type": "object" }),
        ),
        tool(
            "get_domain_stats",
            "Per-domain query statistics from the query log.",
            json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string" },
                    "from": { "type": "string", "format": "date-time" },
                    "to": { "type": "string", "format": "date-time" }
                },
                "required": ["domain"]
            }),
        ),
        tool(
            "get_stats_timeseries",
            "Query volume over time (hourly buckets by default).",
            json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string", "format": "date-time" },
                    "to": { "type": "string", "format": "date-time" },
                    "profile_id": { "type": "string" }
                }
            }),
        ),
        tool(
            "resolve_client",
            "Find a client by exact display name or IP address. Returns mcp.ambiguous_client when multiple match.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Exact client name or IP" }
                },
                "required": ["query"]
            }),
        ),
    ]
}

fn tool(name: &'static str, description: &'static str, schema_value: Value) -> Tool {
    Tool::new(name, description, schema(schema_value)).with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .idempotent(true)
            .open_world(false),
    )
}

pub(crate) fn validate_arguments(name: &str, arguments: Option<JsonObject>) -> bool {
    match name {
        "classify_domain" => parse_arguments::<DomainArgs>(arguments)
            .and_then(DomainArgs::domain)
            .is_ok(),
        "list_zone_records" => parse_arguments::<ZoneArgs>(arguments)
            .and_then(ZoneArgs::zone_id)
            .is_ok(),
        "get_domain_stats" => parse_arguments::<DomainStatsArgs>(arguments)
            .and_then(DomainStatsArgs::into_params)
            .is_ok(),
        "get_stats_timeseries" => parse_arguments::<TimeseriesArgs>(arguments)
            .and_then(TimeseriesArgs::into_params)
            .is_ok(),
        "resolve_client" => parse_arguments::<ResolveArgs>(arguments)
            .and_then(ResolveArgs::into_params)
            .is_ok(),
        "list_blocked_services" => parse_arguments::<LocaleArgs>(arguments).is_ok(),
        "list_alerts"
        | "list_filter_lists"
        | "list_filter_sets"
        | "list_policy_views"
        | "list_resolver_upstreams"
        | "list_domain_zones"
        | "list_listeners"
        | "list_policy_records" => true,
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
        "classify_domain" => classify_domain(arguments, server, context).await,
        "list_alerts" => simple_list("list_alerts", server.backend.list_alerts(), context, alerts_json).await,
        "list_filter_lists" => {
            simple_list("list_filter_lists", server.backend.list_filter_lists(), context, filter_lists_json).await
        }
        "list_filter_sets" => {
            simple_list("list_filter_sets", server.backend.list_filter_sets(), context, filter_sets_json).await
        }
        "list_policy_views" => {
            simple_list("list_policy_views", server.backend.list_policy_views(), context, policy_views_json).await
        }
        "list_resolver_upstreams" => {
            simple_list(
                "list_resolver_upstreams",
                server.backend.list_resolver_upstreams(),
                context,
                upstreams_json,
            )
            .await
        }
        "list_blocked_services" => list_blocked_services(arguments, server, context).await,
        "list_domain_zones" => {
            simple_list("list_domain_zones", server.backend.list_domain_zones(), context, zones_json).await
        }
        "list_zone_records" => list_zone_records(arguments, server, context).await,
        "list_listeners" => {
            simple_list("list_listeners", server.backend.list_listeners(), context, listeners_json).await
        }
        "list_policy_records" => {
            simple_list(
                "list_policy_records",
                server.backend.list_policy_records(),
                context,
                policy_records_json,
            )
            .await
        }
        "get_domain_stats" => get_domain_stats(arguments, server, context).await,
        "get_stats_timeseries" => get_stats_timeseries(arguments, server, context).await,
        "resolve_client" => resolve_client(arguments, server, context).await,
        other => tool_error(
            McpError::ToolNotFound { tool: other.into() }.code(),
            json!({ "tool": other }),
        ),
    }
}

async fn simple_list<T, F>(
    tool: &'static str,
    future: impl std::future::Future<Output = Result<T, crate::backend::BackendError>>,
    context: RequestContext<RoleServer>,
    map: F,
) -> CallToolResult
where
    F: FnOnce(T) -> Value,
{
    match backend_call(tool, &context, future).await {
        Ok(value) => tool_ok(map(value)),
        Err(error) => error,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainArgs {
    domain: String,
}

impl DomainArgs {
    fn domain(self) -> Result<String, CallToolResult> {
        canonicalize(&self.domain).map_err(|_| invalid_input("domain is not valid"))
    }
}

async fn classify_domain(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let domain = match parse_arguments::<DomainArgs>(arguments).and_then(DomainArgs::domain) {
        Ok(domain) => domain,
        Err(error) => return error,
    };
    match backend_call(
        "classify_domain",
        &context,
        server.backend.classify_domain(&domain),
    )
    .await
    {
        Ok(result) => tool_ok(classify_json(&result)),
        Err(error) => error,
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocaleArgs {
    locale: Option<String>,
}

async fn list_blocked_services(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let locale = parse_arguments::<LocaleArgs>(arguments)
        .map(|args| args.locale)
        .unwrap_or_default();
    match backend_call(
        "list_blocked_services",
        &context,
        server.backend.list_blocked_services(locale.as_deref()),
    )
    .await
    {
        Ok(result) => tool_ok(json!({
            "available": result.available,
            "items": result.items,
        })),
        Err(error) => error,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneArgs {
    zone_id: String,
}

impl ZoneArgs {
    fn zone_id(self) -> Result<String, CallToolResult> {
        if self.zone_id.trim().is_empty() {
            return Err(invalid_input("zone_id is required"));
        }
        Ok(self.zone_id)
    }
}

async fn list_zone_records(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let zone_id = match parse_arguments::<ZoneArgs>(arguments).and_then(ZoneArgs::zone_id) {
        Ok(id) => id,
        Err(error) => return error,
    };
    match backend_call(
        "list_zone_records",
        &context,
        server.backend.list_zone_records(&zone_id),
    )
    .await
    {
        Ok(result) => tool_ok(zones_records_json(&result)),
        Err(error) => error,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainStatsArgs {
    domain: String,
    from: Option<String>,
    to: Option<String>,
}

impl DomainStatsArgs {
    fn into_params(self) -> Result<DomainStatsParams, CallToolResult> {
        let domain = canonicalize(&self.domain).map_err(|_| invalid_input("domain is not valid"))?;
        Ok(DomainStatsParams {
            domain,
            from: self.from,
            to: self.to,
        })
    }
}

async fn get_domain_stats(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params =
        match parse_arguments::<DomainStatsArgs>(arguments).and_then(DomainStatsArgs::into_params) {
            Ok(params) => params,
            Err(error) => return error,
        };
    match backend_call(
        "get_domain_stats",
        &context,
        server.backend.get_domain_stats(params),
    )
    .await
    {
        Ok(value) => tool_ok(value),
        Err(error) => error,
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeseriesArgs {
    from: Option<String>,
    to: Option<String>,
    profile_id: Option<String>,
}

impl TimeseriesArgs {
    fn into_params(self) -> Result<StatsTimeseriesParams, CallToolResult> {
        Ok(StatsTimeseriesParams {
            from: self.from,
            to: self.to,
            profile_id: self.profile_id,
        })
    }
}

async fn get_stats_timeseries(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params =
        match parse_arguments::<TimeseriesArgs>(arguments).and_then(TimeseriesArgs::into_params) {
            Ok(params) => params,
            Err(error) => return error,
        };
    match backend_call(
        "get_stats_timeseries",
        &context,
        server.backend.get_stats_timeseries(params),
    )
    .await
    {
        Ok(value) => tool_ok(value),
        Err(error) => error,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArgs {
    query: String,
}

impl ResolveArgs {
    fn into_params(self) -> Result<ResolveClientParams, CallToolResult> {
        let query = self.query.trim();
        if query.is_empty() {
            return Err(invalid_input("query is required"));
        }
        Ok(ResolveClientParams {
            query: query.to_owned(),
        })
    }
}

async fn resolve_client(
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    let params = match parse_arguments::<ResolveArgs>(arguments).and_then(ResolveArgs::into_params) {
        Ok(params) => params,
        Err(error) => return error,
    };
    match backend_call(
        "resolve_client",
        &context,
        server.backend.resolve_client(params),
    )
    .await
    {
        Ok(result) => tool_ok(json!({
            "clients": result.clients.iter().map(client_json).collect::<Vec<_>>(),
            "has_more": result.has_more,
            "next_offset": result.next_offset,
        })),
        Err(error) => error,
    }
}

fn client_json(client: &crate::dto::ClientInfo) -> Value {
    json!({
        "id": sanitize(&client.id, CAP_LIST_ID),
        "display_name": sanitize(&client.display_name, CAP_CLIENT_NAME),
        "source": sanitize(&client.source, CAP_LIST_ID),
        "addresses": client.addresses.iter().map(|a| sanitize(a, CAP_CLIENT_NAME)).collect::<Vec<_>>(),
    })
}

fn classify_json(result: &ClassifyDomainResult) -> Value {
    json!({
        "domain": sanitize(&result.domain, CAP_DOMAIN),
        "kind": sanitize(&result.kind, CAP_LIST_ID),
        "category": result.category.as_ref().map(|c| sanitize(c, CAP_LIST_ID)),
        "name": result.name.as_ref().map(|n| sanitize(n, CAP_CLIENT_NAME)),
        "source": sanitize(&result.source, CAP_LIST_ID),
    })
}

fn alerts_json(result: ListAlertsResult) -> Value {
    json!({
        "active_count": result.active_count,
        "items": result.items,
    })
}

fn filter_lists_json(result: crate::dto::ListFilterListsResult) -> Value {
    json!({
        "filter_lists": result.filter_lists.iter().map(|l| json!({
            "id": sanitize(&l.id, CAP_LIST_ID),
            "name": sanitize(&l.name, CAP_CLIENT_NAME),
            "enabled": l.enabled,
        })).collect::<Vec<_>>(),
    })
}

fn filter_sets_json(result: crate::dto::ListFilterSetsResult) -> Value {
    json!({
        "filter_sets": result.filter_sets.iter().map(|s| json!({
            "id": sanitize(&s.id, CAP_LIST_ID),
            "name": sanitize(&s.name, CAP_CLIENT_NAME),
        })).collect::<Vec<_>>(),
    })
}

fn policy_views_json(result: crate::dto::ListPolicyViewsResult) -> Value {
    json!({
        "views": result.views.iter().map(|v| json!({
            "id": sanitize(&v.id, CAP_LIST_ID),
            "profile_id": sanitize(&v.profile_id, CAP_LIST_ID),
            "is_default": v.is_default,
        })).collect::<Vec<_>>(),
    })
}

fn upstreams_json(result: crate::dto::ListResolverUpstreamsResult) -> Value {
    json!({
        "items": result.items.iter().map(|u| json!({
            "address": sanitize(&u.address, CAP_CLIENT_NAME),
            "state": sanitize(&u.state, CAP_LIST_ID),
        })).collect::<Vec<_>>(),
    })
}

fn zones_json(result: crate::dto::ListDomainZonesResult) -> Value {
    json!({
        "zones": result.zones.iter().map(|z| json!({
            "id": sanitize(&z.id, CAP_LIST_ID),
            "name": sanitize(&z.name, CAP_DOMAIN),
        })).collect::<Vec<_>>(),
    })
}

fn zones_records_json(result: &crate::dto::ListZoneRecordsResult) -> Value {
    json!({
        "zone_id": sanitize(&result.zone_id, CAP_LIST_ID),
        "records": result.records.iter().map(|r| json!({
            "id": sanitize(&r.id, CAP_LIST_ID),
            "name": sanitize(&r.name, CAP_DOMAIN),
            "type": sanitize(&r.r#type, CAP_LIST_ID),
            "content": sanitize(&r.content, CAP_CLIENT_NAME),
            "proxied": r.proxied,
            "ttl": r.ttl,
        })).collect::<Vec<_>>(),
    })
}

fn listeners_json(result: crate::dto::ListListenersResult) -> Value {
    json!({ "listeners": result.listeners })
}

fn policy_records_json(result: crate::dto::ListPolicyRecordsResult) -> Value {
    json!({ "records": result.records })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_args_reject_empty_query() {
        assert!(!validate_arguments(
            "resolve_client",
            Some(serde_json::from_value(json!({ "query": "  " })).unwrap())
        ));
    }

    #[test]
    fn classify_requires_domain() {
        assert!(!validate_arguments(
            "classify_domain",
            Some(serde_json::Map::new())
        ));
    }
}
