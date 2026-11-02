//! Server handler and tool catalog.
//!
//! Each implemented tool lives in a submodule and is registered on
//! [`McpServer`] by the `#[tool_router]` macro. The per-request factory clones
//! the shared handle.
//!
//! Listing and dispatch are overridden here because the catalog is
//! gate-aware: `write_tools_enabled = false` hides the six write tools and a
//! dispatched write tool is denied before it can touch the backend. All tools
//! are defined statically and dispatched manually so input failures stay tool
//! results rather than JSON-RPC errors.

pub mod read;
pub mod write;

mod v2_read;
mod v2_write;

use std::borrow::Cow;
use std::future::Future;

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, GetPromptRequestParams,
    GetPromptResponse, Implementation, JsonObject, ListPromptsResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, Prompt, PromptMessage, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, Resource, ResourceContents, ResultType,
    Role, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool_handler};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::backend::{BackendError, McpBackend};
use crate::config::McpConfig;
use crate::dto::TokenInfo;
use crate::error::McpError;
use crate::protected::ProtectedDomains;
use crate::result::tool_error;

/// Shared state cloned into every per-request server instance.
///
/// Crate-private on purpose: `dnscraft_mcp::service` is the only supported
/// mounting path, so a caller cannot expose the tools by constructing a raw
/// server that bypasses [`crate::transport::McpTransport`]'s authentication.
#[derive(Clone)]
pub(crate) struct McpServer {
    pub(crate) backend: std::sync::Arc<dyn McpBackend>,
    pub(crate) config: McpConfig,
    /// Built once per server handle. `Err` means the configured list is
    /// malformed; write tools fail closed with that config error.
    pub(crate) protected: Result<ProtectedDomains, McpError>,
}

impl McpServer {
    /// A server handle over `backend` and `config`.
    pub(crate) fn new(backend: std::sync::Arc<dyn McpBackend>, config: McpConfig) -> Self {
        let protected = ProtectedDomains::new(config.protected_domains.iter().cloned());
        Self {
            backend,
            config,
            protected,
        }
    }

    /// All tools: macro `get_status`, read/write catalog and v2 extensions.
    fn catalog(&self) -> Vec<Tool> {
        let mut tools = Self::tool_router().list_all();
        tools.extend(read::tool_definitions());
        tools.extend(v2_read::tool_definitions());
        tools.extend(write::tool_definitions());
        tools.extend(v2_write::tool_definitions());
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        tools
    }

    fn listed_tools(&self) -> Vec<Tool> {
        self.catalog()
            .into_iter()
            .filter(|tool| {
                self.config.write_tools_enabled
                    || (!write::is_write_tool(&tool.name)
                        && !v2_write::is_v2_write_tool(&tool.name))
            })
            .collect()
    }
}

/// Parse tool arguments, mapping a deserialization failure to a tool result.
pub(crate) fn parse_arguments<T: DeserializeOwned>(
    arguments: Option<JsonObject>,
) -> Result<T, CallToolResult> {
    serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
        .map_err(|_| invalid_input("arguments do not match the input schema"))
}

/// Parse and validate one tool's raw JSON input without performing I/O.
///
/// This is the fuzzing entry point (M26). `tool` is one of the 14 catalog
/// names and `json` is the raw `arguments` object. It runs the same
/// `serde_json` decode with `deny_unknown_fields` and the same per-tool value
/// checks as dispatch. Backend, scope, write-gate and protected-domain checks
/// are not input parsing and are not covered here; config-dependent duration
/// maxima likewise stay in the handlers.
///
/// `get_status` takes no arguments, so any JSON object is accepted.
///
/// # Errors
///
/// Returns [`McpError::ToolNotFound`] for a name outside the catalog and
/// [`McpError::InvalidInput`] for malformed JSON, a non-object document or
/// arguments the tool's parser rejects. The detail is collapsed to a stable
/// reason because this entry point has no tool-result envelope.
#[doc(hidden)]
pub fn parse_mcp_tool_input(tool: &str, json: &[u8]) -> Result<(), McpError> {
    let value: Value =
        serde_json::from_slice(json).map_err(|_| invalid_arguments("malformed JSON"))?;
    let Value::Object(arguments) = value else {
        return Err(invalid_arguments("arguments must be a JSON object"));
    };
    let valid = match tool {
        "get_status" => true,
        name if read::is_read_tool(name) => read::validate_arguments(name, Some(arguments)),
        name if v2_read::is_v2_read_tool(name) => v2_read::validate_arguments(name, Some(arguments)),
        name if write::is_write_tool(name) => write::validate_arguments(name, Some(arguments)),
        name if v2_write::is_v2_write_tool(name) => {
            v2_write::validate_arguments(name, Some(arguments))
        }
        _ => {
            return Err(McpError::ToolNotFound {
                tool: tool.to_owned(),
            });
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_arguments("arguments do not match the input schema"))
    }
}

fn invalid_arguments(reason: &'static str) -> McpError {
    McpError::InvalidInput {
        reason: reason.to_owned(),
    }
}

/// A `mcp.invalid_input` tool result with a fixed reason.
pub(crate) fn invalid_input(reason: &'static str) -> CallToolResult {
    tool_error(
        McpError::InvalidInput {
            reason: reason.into(),
        }
        .code(),
        json!({ "reason": reason }),
    )
}

/// Convert a JSON object literal into a tool input schema.
pub(crate) fn schema(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    }
}

/// Await a backend call, mapping cancellation and errors to the tool shape.
pub(crate) async fn backend_call<T, F>(
    tool: &'static str,
    context: &RequestContext<RoleServer>,
    future: F,
) -> Result<T, CallToolResult>
where
    F: Future<Output = Result<T, BackendError>>,
{
    let outcome = tokio::select! {
        result = future => Some(result),
        _ = context.ct.cancelled() => None,
    };
    let Some(result) = outcome else {
        return Err(tool_error(
            "control_api.internal",
            json!({ "reason": "cancelled" }),
        ));
    };
    result.map_err(|error| {
        tracing::warn!(tool, code = error.code(), "{} backend error", tool);
        tool_error(error.code(), error.params().unwrap_or_else(|| json!({})))
    })
}

/// The token `transport` validated and attached to the request.
pub(crate) fn token_from(context: &RequestContext<RoleServer>) -> Option<&TokenInfo> {
    context
        .extensions
        .get::<http::request::Parts>()?
        .extensions
        .get::<TokenInfo>()
}

/// Reject a tool call that carries no validated [`TokenInfo`].
///
/// `transport` always inserts the token after authentication. This guard is
/// defence in depth so a read tool cannot run if a server were ever mounted
/// without that wrapper, mirroring the check in `write::call`.
pub(crate) fn require_token(token: Option<&TokenInfo>) -> Result<(), CallToolResult> {
    match token {
        Some(_) => Ok(()),
        None => Err(tool_error("control_api.auth.unauthenticated", json!({}))),
    }
}

const INSTRUCTIONS_TEXT: &str = "\
1. Never invent domains, clients, filter sets, or DNS answers — use tools or ask the user.\n\
2. Prefer DNScraft tools over assumptions.\n\
3. If input is incomplete or ambiguous, ask the user or return a clarification error.\n\
4. Read tools are safe; confirm with the user before any write tool.\n\
5. Call classify_domain before allow_temporarily or propose_exception; tracking domains need acknowledge_tracking after explicit user consent.\n\
6. When multiple clients or filter sets match, disambiguate before acting.";

#[tool_handler(name = "dnscraft-mcp")]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_instructions(INSTRUCTIONS_TEXT)
        .with_server_info(Implementation::new("dnscraft-mcp", env!("CARGO_PKG_VERSION")))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        if self.config.legacy_session_mode {
            Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
        } else {
            Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let supports_cache = context
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
        Ok(ListToolsResult {
            result_type: Some(ResultType::COMPLETE),
            tools: self.listed_tools(),
            meta: None,
            next_cursor: None,
            ttl_ms: supports_cache.then_some(0),
            // The list depends on server config and the caller's endpoint, not
            // on public data, so never let a shared cache serve it.
            cache_scope: supports_cache.then_some(CacheScope::Private),
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.catalog().into_iter().find(|tool| tool.name == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.as_ref();
        let token_id = token_from(&context).map(|token| token.token_id.clone());
        let result = if name == "get_status" {
            self.get_status(context).await
        } else if write::is_write_tool(name) {
            write::call(name, request.arguments, self, context).await
        } else if v2_write::is_v2_write_tool(name) {
            v2_write::call(name, request.arguments, self, context).await
        } else if read::is_read_tool(name) {
            read::call(name, request.arguments, self, context).await
        } else if v2_read::is_v2_read_tool(name) {
            v2_read::call(name, request.arguments, self, context).await
        } else {
            tool_error(
                McpError::ToolNotFound { tool: name.into() }.code(),
                json!({ "tool": name }),
            )
        };
        // Telemetry counter `mcp.tool_calls{tool_name, token_id, result}`. It is
        // a structured tracing event (no metrics exporter exists yet). Unknown
        // names collapse to one label so a client cannot grow the label set.
        let tool_name = if self.get_tool(name).is_some() {
            name
        } else {
            "unknown"
        };
        tracing::info!(
            target: "dnscraft_mcp::telemetry",
            counter = "mcp.tool_calls",
            tool_name,
            token_id = token_id.as_deref().unwrap_or(""),
            result = if result.is_error == Some(true) { "error" } else { "success" },
            "mcp tool call"
        );
        Ok(result.into())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, rmcp::ErrorData> {
        Ok(ListPromptsResult {
            result_type: Some(ResultType::COMPLETE),
            prompts: vec![
                Prompt::from_raw(
                    "diagnose_block",
                    Some("Workflow: resolve the client, explain_block or test_query, then summarize for the user. Ask when inputs are missing."),
                    None,
                ),
                Prompt::from_raw(
                    "network_health_check",
                    Some("Workflow: get_status, list_alerts, list_resolver_upstreams. Report issues without guessing."),
                    None,
                ),
                Prompt::from_raw(
                    "temporary_access",
                    Some("Workflow: classify_domain first; if tracking, get explicit user consent before allow_temporarily with acknowledge_tracking."),
                    None,
                ),
            ],
            meta: None,
            next_cursor: None,
            ttl_ms: None,
            cache_scope: None,
        })
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, rmcp::ErrorData> {
        let text = match request.name.as_str() {
            "diagnose_block" => "Use resolve_client, explain_block, and test_query. Ask for domain and device when unknown.",
            "network_health_check" => "Use get_status, list_alerts, and list_resolver_upstreams. Do not invent health data.",
            "temporary_access" => "Use classify_domain before allow_temporarily. Tracking domains require acknowledge_tracking after the user explicitly agrees.",
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    "unknown prompt",
                    Some(json!({ "name": other })),
                ));
            }
        };
        Ok(GetPromptResponse::Complete(
            rmcp::model::GetPromptResult::new(vec![PromptMessage::new_text(
                Role::Assistant,
                text,
            )])
            .with_description(text),
        ))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, rmcp::ErrorData> {
        Ok(ListResourcesResult {
            result_type: Some(ResultType::COMPLETE),
            resources: vec![
                Resource::new("dnscraft://status", "status")
                    .with_description("Node status snapshot")
                    .with_mime_type("application/json"),
                Resource::new("dnscraft://alerts", "alerts")
                    .with_description("Active alerts")
                    .with_mime_type("application/json"),
                Resource::new("dnscraft://filter-lists", "filter-lists")
                    .with_description("Filter list catalog")
                    .with_mime_type("application/json"),
                Resource::new("dnscraft://policy/map", "policy-map")
                    .with_description("Policy views")
                    .with_mime_type("application/json"),
            ],
            meta: None,
            next_cursor: None,
            ttl_ms: None,
            cache_scope: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, rmcp::ErrorData> {
        if require_token(token_from(&context)).is_err() {
            return Err(rmcp::ErrorData::invalid_request(
                "authentication required",
                None,
            ));
        }
        let payload = match request.uri.as_str() {
            "dnscraft://status" => {
                let status = self
                    .backend
                    .get_status()
                    .await
                    .map_err(resource_backend_err)?;
                serde_json::to_string(&read::status_json(&status)).map_err(resource_internal_err)?
            }
            "dnscraft://alerts" => {
                let alerts = self
                    .backend
                    .list_alerts()
                    .await
                    .map_err(resource_backend_err)?;
                serde_json::to_string(&json!({
                    "active_count": alerts.active_count,
                    "items": alerts.items,
                }))
                .map_err(resource_internal_err)?
            }
            "dnscraft://filter-lists" => {
                let lists = self
                    .backend
                    .list_filter_lists()
                    .await
                    .map_err(resource_backend_err)?;
                serde_json::to_string(&lists).map_err(resource_internal_err)?
            }
            "dnscraft://policy/map" => {
                let views = self
                    .backend
                    .list_policy_views()
                    .await
                    .map_err(resource_backend_err)?;
                serde_json::to_string(&views).map_err(resource_internal_err)?
            }
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    "unknown resource",
                    Some(json!({ "uri": other })),
                ));
            }
        };
        Ok(ReadResourceResponse::Complete(
            rmcp::model::ReadResourceResult::new(vec![ResourceContents::TextResourceContents {
                uri: request.uri,
                mime_type: Some("application/json".into()),
                text: payload,
                meta: None,
            }]),
        ))
    }
}

fn resource_backend_err(error: BackendError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(error.code().to_owned(), error.params())
}

fn resource_internal_err(error: serde_json::Error) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(
        "control_api.internal",
        Some(json!({ "reason": error.to_string() })),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_input_for_every_tool() {
        let cases = [
            ("search_query_log", r#"{"domain":"example.com","limit":10}"#),
            (
                "get_query",
                r#"{"id":"123e4567-e89b-12d3-a456-426614174000"}"#,
            ),
            ("explain_block", r#"{"domain":"example.com","qtype":"A"}"#),
            (
                "test_query",
                r#"{"domain":"example.net","source_ip":"192.0.2.1"}"#,
            ),
            (
                "get_stats",
                r#"{"from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}"#,
            ),
            ("list_clients", r#"{"limit":10,"source":"unifi"}"#),
            ("list_mcp_rules", r#"{"kind":"pauses","limit":10}"#),
            ("get_status", "{}"),
            (
                "allow_temporarily",
                r#"{"domain":"example.com","duration":"PT15M"}"#,
            ),
            ("add_rule", r#"{"domain":"ads.example"}"#),
            ("remove_rule", r#"{"domain":"example.com"}"#),
            ("pause_filter_set", r#"{"duration":"PT1H"}"#),
            ("resume_filter_set", r#"{"filter_set_id":"default"}"#),
            ("classify_domain", r#"{"domain":"ads.example.com"}"#),
            ("list_alerts", "{}"),
            ("resolve_client", r#"{"query":"phone"}"#),
            ("cancel_temporary_allow", r#"{"domain":"ads.example.com"}"#),
            ("flush_cache", "{}"),
            (
                "set_blocked_service",
                r#"{"service_id":"youtube","enabled":true}"#,
            ),
            (
                "create_zone_record",
                r#"{"zone_id":"z1","name":"www","type":"A","content":"192.0.2.1"}"#,
            ),
        ];
        for (tool, json) in cases {
            assert!(
                parse_mcp_tool_input(tool, json.as_bytes()).is_ok(),
                "{tool}: {json}"
            );
        }
    }

    #[test]
    fn rejects_malformed_unknown_and_hostile_input() {
        for json in [
            r#"{"domain":"#,
            "[1,2,3]",
            r#"{"domain":"example.com","bogus":1}"#,
            r#"{"domain":"example.com$dnsrewrite=127.0.0.1"}"#,
            r#"{"domain":"||ads.example^"}"#,
            r#"{"domain":"*.example.com"}"#,
            r#"{"domain":""}"#,
            r#"{"id":"not-a-uuid"}"#,
            r#"{"limit":"fifty"}"#,
        ] {
            assert!(
                parse_mcp_tool_input("add_rule", json.as_bytes()).is_err(),
                "{json}"
            );
        }
        assert!(parse_mcp_tool_input("nope", b"{}").is_err());
    }

    #[test]
    fn read_dispatch_rejects_a_missing_token() {
        // `read::call` and `get_status` apply this guard before any work.
        let error = require_token(None).unwrap_err();
        assert_eq!(error.is_error, Some(true));
        assert_eq!(
            error.structured_content.unwrap()["error"]["code"],
            "control_api.auth.unauthenticated"
        );
        let token = crate::dto::TokenInfo {
            token_id: "tok-read".into(),
            scope: crate::dto::TokenScope::McpRead,
            actor_id: "actor".into(),
        };
        assert!(require_token(Some(&token)).is_ok());
    }
}
