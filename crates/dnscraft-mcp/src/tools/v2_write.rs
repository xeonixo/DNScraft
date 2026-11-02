//! MCP v2 write tools.

use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{McpServer, invalid_input, parse_arguments, schema, token_from};
use crate::dto::{
    AuditResult, CancelTempAllowParams, DeletePolicyRecordParams, DeleteZoneRecordParams,
    FlushCacheParams, SetBlockedServiceParams, TokenInfo, TokenScope, UpsertPolicyRecordParams,
    ZoneRecordWriteParams,
};
use crate::error::McpError;
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, sanitize};

use super::write::{audit_failed, record, validate_domain};

pub const V2_WRITE_TOOL_NAMES: [&str; 8] = [
    "cancel_temporary_allow",
    "flush_cache",
    "set_blocked_service",
    "create_zone_record",
    "update_zone_record",
    "delete_zone_record",
    "upsert_policy_record",
    "delete_policy_record",
];

pub fn is_v2_write_tool(name: &str) -> bool {
    V2_WRITE_TOOL_NAMES.contains(&name)
}

pub fn tool_definitions() -> Vec<Tool> {
    vec![
        Tool::new(
            "cancel_temporary_allow",
            "Cancel an active temporary allow for a domain. Requires mcp:write and write_tools_enabled.",
            schema(json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string" },
                    "filter_set_id": { "type": "string" }
                },
                "required": ["domain"]
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(true)),
        Tool::new(
            "flush_cache",
            "Flush the resolver cache for one domain or the entire cache. Requires mcp:write.",
            schema(json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Optional domain scope" }
                }
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false)),
        Tool::new(
            "set_blocked_service",
            "Enable or disable a blocked-service category in a filter set.",
            schema(json!({
                "type": "object",
                "properties": {
                    "service_id": { "type": "string" },
                    "enabled": { "type": "boolean" },
                    "filter_set_id": { "type": "string" }
                },
                "required": ["service_id", "enabled"]
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false)),
        Tool::new(
            "create_zone_record",
            "Create a DNS record in an attached public zone.",
            schema(zone_record_schema(false)),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false)),
        Tool::new(
            "update_zone_record",
            "Update a DNS record in an attached public zone.",
            schema(zone_record_schema(true)),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(false)),
        Tool::new(
            "delete_zone_record",
            "Delete a DNS record from an attached public zone.",
            schema(json!({
                "type": "object",
                "properties": {
                    "zone_id": { "type": "string" },
                    "record_id": { "type": "string" }
                },
                "required": ["zone_id", "record_id"]
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(true)),
        Tool::new(
            "upsert_policy_record",
            "Create or replace a local Split-DNS policy record. Overrides may use string/@public/\"\" or structured {mode:data|public|no_answer|addresses}. addresses (A/AAAA) is only valid on CNAME records for hairpin answers.",
            schema(json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string" },
                    "ttl": { "type": "integer" },
                    "rdata": {},
                    "overrides": { "type": "object" },
                    "comment": { "type": "string" },
                    "tags": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["name", "type", "rdata"]
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(true)),
        Tool::new(
            "delete_policy_record",
            "Delete a local Split-DNS policy record by name and type.",
            schema(json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string" }
                },
                "required": ["name", "type"]
            })),
        )
        .with_annotations(ToolAnnotations::new().destructive(true).idempotent(true)),
    ]
}

fn zone_record_schema(update: bool) -> Value {
    let mut props = json!({
        "zone_id": { "type": "string" },
        "name": { "type": "string" },
        "type": { "type": "string" },
        "content": { "type": "string" },
        "proxied": { "type": "boolean" },
        "ttl": { "type": "integer" }
    });
    if update {
        props["record_id"] = json!({ "type": "string" });
    }
    let required = if update {
        vec!["zone_id", "record_id", "name", "type", "content"]
    } else {
        vec!["zone_id", "name", "type", "content"]
    };
    json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

pub(crate) fn validate_arguments(name: &str, arguments: Option<JsonObject>) -> bool {
    match name {
        "cancel_temporary_allow" => parse_arguments::<CancelArgs>(arguments)
            .is_ok_and(|a| validate_domain(&a.domain).is_ok()),
        "flush_cache" => parse_arguments::<FlushArgs>(arguments).is_ok(),
        "set_blocked_service" => parse_arguments::<ServiceArgs>(arguments).is_ok(),
        "create_zone_record" => parse_arguments::<ZoneWriteArgs>(arguments)
            .is_ok_and(|a| a.record_id.is_none()),
        "update_zone_record" => parse_arguments::<ZoneWriteArgs>(arguments)
            .is_ok_and(|a| a.record_id.as_ref().is_some_and(|id| !id.is_empty())),
        "delete_zone_record" => parse_arguments::<DeleteZoneArgs>(arguments).is_ok(),
        "upsert_policy_record" => parse_arguments::<UpsertPolicyArgs>(arguments).is_ok_and(|a| {
            !a.name.trim().is_empty() && !a.record_type.trim().is_empty() && !a.rdata.is_null()
        }),
        "delete_policy_record" => parse_arguments::<DeletePolicyArgs>(arguments)
            .is_ok_and(|a| !a.name.trim().is_empty() && !a.record_type.trim().is_empty()),
        _ => false,
    }
}

pub(crate) async fn call(
    name: &str,
    arguments: Option<JsonObject>,
    server: &McpServer,
    context: RequestContext<RoleServer>,
) -> CallToolResult {
    if !server.config.write_tools_enabled {
        return tool_error(McpError::WriteToolsDisabled.code(), json!({}));
    }
    let Some(token) = token_from(&context).cloned() else {
        return tool_error("control_api.auth.unauthenticated", json!({}));
    };
    if token.scope != TokenScope::McpWrite {
        return tool_error("control_api.auth.insufficient_scope", json!({}));
    }
    match name {
        "cancel_temporary_allow" => cancel_temporary_allow(arguments, server, &token).await,
        "flush_cache" => flush_cache(arguments, server, &token).await,
        "set_blocked_service" => set_blocked_service(arguments, server, &token).await,
        "create_zone_record" => write_zone_record(arguments, server, &token, false).await,
        "update_zone_record" => write_zone_record(arguments, server, &token, true).await,
        "delete_zone_record" => delete_zone_record(arguments, server, &token).await,
        "upsert_policy_record" => upsert_policy_record(arguments, server, &token).await,
        "delete_policy_record" => delete_policy_record_tool(arguments, server, &token).await,
        other => tool_error(
            "control_api.internal",
            json!({ "reason": "not_implemented", "tool": other }),
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelArgs {
    domain: String,
    filter_set_id: Option<String>,
}

async fn cancel_temporary_allow(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<CancelArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let domain = match validate_domain(&args.domain) {
        Ok(domain) => domain,
        Err(error) => return error,
    };
    let params = CancelTempAllowParams {
        domain: domain.clone(),
        filter_set_id: args.filter_set_id.clone(),
    };
    match server.backend.cancel_temporary_allow(params).await {
        Ok(result) => {
            let after = json!({
                "domain": sanitize(&domain, CAP_DOMAIN),
                "filter_set_id": sanitize(&result.filter_set_id, CAP_LIST_ID),
                "removed": result.removed,
            });
            if record(
                server,
                token,
                "mcp.cancel_temporary_allow",
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed("mcp.cancel_temporary_allow");
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlushArgs {
    domain: Option<String>,
}

async fn flush_cache(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = parse_arguments::<FlushArgs>(arguments).unwrap_or_default();
    let domain = if let Some(raw) = args.domain {
        match validate_domain(&raw) {
            Ok(domain) => Some(domain),
            Err(error) => return error,
        }
    } else {
        None
    };
    let params = FlushCacheParams {
        domain: domain.clone(),
    };
    match server.backend.flush_cache(params).await {
        Ok(result) => {
            let after = json!({
                "flushed": result.flushed,
                "domain": result.domain.as_ref().map(|d| sanitize(d, CAP_DOMAIN)),
            });
            if record(
                server,
                token,
                "mcp.flush_cache",
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed("mcp.flush_cache");
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceArgs {
    service_id: String,
    enabled: bool,
    filter_set_id: Option<String>,
}

async fn set_blocked_service(
    arguments: Option<JsonObject>,
    server: &McpServer,
    _token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<ServiceArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    if args.service_id.trim().is_empty() {
        return invalid_input("service_id is required");
    }
    let params = SetBlockedServiceParams {
        service_id: args.service_id.clone(),
        enabled: args.enabled,
        filter_set_id: args.filter_set_id.clone(),
    };
    match server.backend.set_blocked_service(params).await {
        Ok(result) => tool_ok(json!({
            "service_id": sanitize(&result.service_id, CAP_LIST_ID),
            "filter_set_id": sanitize(&result.filter_set_id, CAP_LIST_ID),
            "enabled": result.enabled,
            "config_version": result.config_version,
        })),
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneWriteArgs {
    zone_id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    proxied: Option<bool>,
    ttl: Option<u32>,
    record_id: Option<String>,
}

impl ZoneWriteArgs {
    fn into_params(self, update: bool) -> Result<ZoneRecordWriteParams, CallToolResult> {
        if self.zone_id.trim().is_empty() {
            return Err(invalid_input("zone_id is required"));
        }
        if update && self.record_id.as_ref().is_none_or(|id| id.trim().is_empty()) {
            return Err(invalid_input("record_id is required"));
        }
        Ok(ZoneRecordWriteParams {
            zone_id: self.zone_id,
            name: self.name,
            r#type: self.record_type,
            content: self.content,
            proxied: self.proxied,
            ttl: self.ttl,
            record_id: self.record_id,
        })
    }
}

async fn write_zone_record(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
    update: bool,
) -> CallToolResult {
    let params = match parse_arguments::<ZoneWriteArgs>(arguments).and_then(|a| a.into_params(update))
    {
        Ok(params) => params,
        Err(error) => return error,
    };
    let action = if update {
        "mcp.update_zone_record"
    } else {
        "mcp.create_zone_record"
    };
    let future = if update {
        server.backend.update_zone_record(params.clone())
    } else {
        server.backend.create_zone_record(params.clone())
    };
    match future.await {
        Ok(result) => {
            let after = json!({
                "zone_id": sanitize(&result.zone_id, CAP_LIST_ID),
                "record": {
                    "id": sanitize(&result.record.id, CAP_LIST_ID),
                    "name": sanitize(&result.record.name, CAP_DOMAIN),
                    "type": sanitize(&result.record.r#type, CAP_LIST_ID),
                    "content": sanitize(&result.record.content, CAP_CLIENT_NAME),
                },
            });
            if record(
                server,
                token,
                action,
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed(action);
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteZoneArgs {
    zone_id: String,
    record_id: String,
}

async fn delete_zone_record(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<DeleteZoneArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let params = DeleteZoneRecordParams {
        zone_id: args.zone_id,
        record_id: args.record_id,
    };
    match server.backend.delete_zone_record(params).await {
        Ok(result) => {
            let after = json!({
                "deleted": result.deleted,
                "zone_id": sanitize(&result.zone_id, CAP_LIST_ID),
                "record_id": sanitize(&result.record_id, CAP_LIST_ID),
            });
            if record(
                server,
                token,
                "mcp.delete_zone_record",
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed("mcp.delete_zone_record");
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpsertPolicyArgs {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: Option<u32>,
    rdata: Value,
    overrides: Option<serde_json::Map<String, Value>>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
}

async fn upsert_policy_record(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<UpsertPolicyArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let params = UpsertPolicyRecordParams {
        name: args.name,
        r#type: args.record_type,
        ttl: args.ttl,
        rdata: args.rdata,
        overrides: args.overrides.map(|map| map.into_iter().collect()),
        comment: args.comment,
        tags: args.tags,
    };
    match server.backend.upsert_policy_record(params).await {
        Ok(result) => {
            let after = json!({
                "version": result.version,
                "record": result.record,
            });
            if record(
                server,
                token,
                "mcp.upsert_policy_record",
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed("mcp.upsert_policy_record");
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePolicyArgs {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

async fn delete_policy_record_tool(
    arguments: Option<JsonObject>,
    server: &McpServer,
    token: &TokenInfo,
) -> CallToolResult {
    let args = match parse_arguments::<DeletePolicyArgs>(arguments) {
        Ok(args) => args,
        Err(error) => return error,
    };
    let params = DeletePolicyRecordParams {
        name: args.name,
        r#type: args.record_type,
    };
    match server.backend.delete_policy_record(params).await {
        Ok(result) => {
            let after = json!({
                "deleted": result.deleted,
                "version": result.version,
                "name": sanitize(&result.name, CAP_DOMAIN),
                "type": sanitize(&result.r#type, CAP_LIST_ID),
            });
            if record(
                server,
                token,
                "mcp.delete_policy_record",
                None,
                Some(after.clone()),
                AuditResult::Success,
                None,
            )
            .await
            .is_err()
            {
                return audit_failed("mcp.delete_policy_record");
            }
            tool_ok(after)
        }
        Err(error) => tool_error(error.code(), error.params().unwrap_or_else(|| json!({}))),
    }
}
