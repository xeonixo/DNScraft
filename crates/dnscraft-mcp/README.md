# dnscraft-mcp

Stateless Model Context Protocol (MCP) server for DNScraft, implementing protocol
revision 2026-07-28 over Streamable HTTP under `POST /mcp/v1`.

The crate owns the protocol and tool layer only. The control API owns the HTTP
listener, the bearer tokens, the rate limits and the audit log, and mounts the
service returned by [`service`](src/lib.rs) at `/mcp/v1`.

See [SPEC-mcp.md](../../docs/SPEC-mcp.md) for the authoritative protocol, tool and
security rules.

## Architecture

```text
control-api
   │  implements McpBackend (all I/O: log, policy, filtering, audit)
   ▼
dnscraft-mcp
   ├── tools/       36 tool definitions + handlers (read and write)
   ├── transport     pure request pre-checks + rmcp Streamable HTTP wrapper
   ├── auth         bearer-token extraction and scope checks
   ├── protected    protected-domain matching
   ├── sanitize     control-character neutralisation and length caps
   ├── config       config keys, defaults and startup validation
   ├── dto          every DTO that crosses the backend boundary
   └── error        stable `mcp.*` codes
```

The crate **depends on no other DNScraft crate**. `McpBackend` is the single
inbound port: `control-api` implements it and every type passed across that
boundary is defined in this crate's `dto` module. Tool handlers therefore never
link to the resolver, filtering, policy or query-log crates directly.

`rmcp` 3.7.0 provides the Streamable HTTP transport, SEP-2243 header validation,
protocol-version negotiation and disconnect cancellation. This crate adds the
DNScraft-specific behaviour around it: bearer authentication, scope checks,
the stable error envelope, per-token request caps, request deadline and the
write-tools gate. The dependency decision is recorded in
[ADR-0006](../../docs/adr/0006-mcp-rmcp-stateless.md).

## Tools

All 36 tools are listed when `write_tools_enabled = true`; with the gate off,
`tools/list` returns only the 22 read tools and every write tool call fails
with `mcp.write_tools_disabled`. Rows are in the order returned by `tools/list`
(alphabetical).

| Tool | Scope | Description |
|---|---|---|
| `add_rule` | `mcp:write` | Add a structured custom block rule to a filter set (no raw syntax, no wildcards). |
| `allow_temporarily` | `mcp:write` | Temporarily allow a blocked domain; call `classify_domain` first; tracking domains need `acknowledge_tracking`. |
| `cancel_temporary_allow` | `mcp:write` | Remove an active temporary allow for a domain. |
| `classify_domain` | `mcp:read` | Classify a domain using the tracker database (tracking / functional / unknown). |
| `create_zone_record` | `mcp:write` | Create a DNS record in an attached public zone. |
| `delete_policy_record` | `mcp:write` | Delete a local Split-DNS policy record by name and type. |
| `delete_zone_record` | `mcp:write` | Delete a DNS record from an attached public zone. |
| `explain_block` | `mcp:read` | Explain why a domain is currently blocked for a profile, without a live DNS query. |
| `flush_cache` | `mcp:write` | Flush the resolver cache for one domain or entirely. |
| `get_domain_stats` | `mcp:read` | Per-domain query statistics from the query log. |
| `get_query` | `mcp:read` | Retrieve one query-log entry with its full decision record. |
| `get_stats` | `mcp:read` | Retrieve DNS statistics for a time range. |
| `get_stats_timeseries` | `mcp:read` | Query volume over time (hourly buckets). |
| `get_status` | `mcp:read` | Get node status: resolver health, listeners, TLS, list updates and uptime. |
| `list_alerts` | `mcp:read` | List active operational alerts. |
| `list_blocked_services` | `mcp:read` | Blocked-services catalog and per–filter-set toggles. |
| `list_clients` | `mcp:read` | List known clients with names, addresses, VLANs and source. |
| `list_domain_zones` | `mcp:read` | List attached public DNS zones. |
| `list_filter_lists` | `mcp:read` | List configured filter lists. |
| `list_filter_sets` | `mcp:read` | List filter sets from configuration. |
| `list_listeners` | `mcp:read` | List listener definitions from configuration. |
| `list_mcp_rules` | `mcp:read` | List MCP-created rules, active temporary allows or active pauses for a filter set. |
| `list_policy_records` | `mcp:read` | List local Split-DNS policy records (incl. overrides, comment, tags). |
| `list_policy_views` | `mcp:read` | List policy views and profile bindings. |
| `list_resolver_upstreams` | `mcp:read` | Resolver upstream health. |
| `list_zone_records` | `mcp:read` | List DNS records in one attached zone. |
| `pause_filter_set` | `mcp:write` | Pause filtering for a filter set for a fixed short duration. |
| `propose_exception` | `mcp:write` | Propose a permanent exception; classify first; owner confirms in the web UI. |
| `remove_rule` | `mcp:write` | Remove a custom block rule that was previously created via MCP. |
| `resolve_client` | `mcp:read` | Resolve a client by exact display name or IP. |
| `resume_filter_set` | `mcp:write` | Resume filtering for a paused filter set. |
| `search_query_log` | `mcp:read` | Search the query log by time, client, domain, protocol, view or outcome. |
| `set_blocked_service` | `mcp:write` | Enable or disable a blocked-service category in a filter set. |
| `test_query` | `mcp:read` | Dry-run a query through the policy engine without writing to the log or cache. |
| `update_zone_record` | `mcp:write` | Update a DNS record in an attached public zone. |
| `upsert_policy_record` | `mcp:write` | Create or replace a local Split-DNS policy record (supports addresses overrides on CNAME). |

Read tools carry `readOnlyHint: true`; write tools carry `destructiveHint: true`.
Tool descriptions are static and are never built from runtime data.

## Limits and defaults

| Setting | Default | Range | Enforced by |
|---|---|---|---|
| `max_concurrent_requests_per_token` | 5 | 1–50 | Per-token in-flight counter |
| `request_timeout` | 60 s | 10–300 s | Per-request deadline |
| `max_request_body_size` | 1 MiB | ≥ 1 byte | Transport (streamed, independent of `Content-Length`) |
| `read_per_second` | 100 | 1–10000 | Per-token read-tool rate |
| `write_per_second` | 20 | 1–10000 | Per-token write-tool rate |
| `auth_per_second` | 10 | 1–10000 | Per-source failed-authentication rate |
| `max_tracked_tokens` | 10000 | 1–1000000 | LRU cap on rate-limit buckets |
| `max_temporary_allow_duration` | 1 h | 5 min–1 h | Lowers the fixed `PT5M`/`PT15M`/`PT1H` set |
| `max_pause_duration` | 1 h | 5 min–1 h | Lowers the fixed `PT5M`/`PT15M`/`PT1H` set |
| `max_custom_rules_per_set` | 100 | 10–1000 | `add_rule` (non-expired rules per filter set) |
| `max_block_rule_lifetime` | 30 d | 1–365 d | Server-set `expires_at` on every MCP-created rule |
| `legacy_session_mode` | `false` | `true`/`false` | Protocol negotiation; `MCP-Protocol-Version` is still required |
| `write_tools_enabled` | `false` | `true`/`false` | Independent gate for the twelve write tools |

`enabled` defaults to `false` as well: the endpoint is opt-in. Result lists default
to 50 items (100 for `list_clients` and `list_mcp_rules`) and cap at 500 per
request. Rate limits use a per-token token bucket: read tools and non-tool
methods use `read_per_second`, write tools use `write_per_second`, and failed
authentication attempts use `auth_per_second` keyed by source. Excess returns
HTTP 429 with `control_api.rate_limited` and `Retry-After`.

The duration maxima can only **lower** the fixed three-value duration set; they
cannot add `PT4H` or any other value. Out-of-range configuration is rejected at
startup with `mcp.config.invalid` (or `mcp.config.protected_domain` for a
malformed protected-domain entry).

## Error codes

Tool-level failures use one shape: `isError: true` plus
`structuredContent.error = {"code": "...", "params": {...}}`. They never become
an HTTP status or a JSON-RPC error.

| Code | When |
|---|---|
| `mcp.tool_not_found` | The `tools/call` name is not a registered tool |
| `mcp.invalid_input` | Input fails the schema, an enum value is not allowed, or a duration is outside the fixed set |
| `mcp.domain_too_broad` | The target is a single-label (TLD-wide) name such as `com` |
| `mcp.write_tools_disabled` | A write tool was called while `write_tools_enabled = false` |
| `mcp.duration_exceeds_maximum` | A duration in the fixed set is above the configured maximum |
| `mcp.rule_limit_exceeded` | The MCP-created rule cap was reached for the filter set |
| `mcp.protected_domain` | The target, an ancestor or a descendant is protected |
| `mcp.config.invalid` | A configuration value is out of range (startup only) |
| `mcp.config.protected_domain` | A `protected_domains` entry is malformed (startup only) |
| `mcp.tracking_domain_refused` | Allow/propose on a tracking-classified domain without `acknowledge_tracking` |
| `mcp.needs_clarification` | Multiple filter sets (or similar) — pick from `params.candidates` |
| `mcp.ambiguous_client` | More than one client matched `resolve_client` |

Protocol-defined JSON-RPC errors, returned as JSON-RPC errors rather than tool
results: `-32601` (method not found, HTTP 404), `-32020` (header mismatch, HTTP
400) and `-32022` (unsupported protocol version, HTTP 400).

HTTP-level rejections use the control-api envelope with a stable code:
`control_api.auth.unauthenticated` (401), `control_api.auth.invalid_origin`
(403), `control_api.auth.invalid_scope` (403), `control_api.not_found` (404),
`control_api.method_not_allowed` (405), `control_api.payload_too_large` (413)
and `control_api.rate_limited` (429).

## Security model

- **Least privilege.** Tokens use dedicated MCP scopes: `mcp:read` for the eight
  read tools and `mcp:write` for the five write tools. Browser/API tokens
  (`viewer`, `admin`) are rejected on `/mcp/v1`, and MCP tokens are rejected on
  `/api/v1`. The write tools have a second, independent configuration gate
  (`write_tools_enabled`, default `false`).
- **Sanitizing.** Every string from DNS, clients, filter lists or the assistant
  is untrusted data. Output passes through `SafeText`, which replaces control
  characters with `U+FFFD` and truncates on a character boundary with known
  caps. Assistant-supplied reasons are sanitized before storage and audit.
- **Protected domains.** Control-plane and infrastructure names (the node's
  public domain, DynDNS names, OIDC issuer, ACME directory, list URLs, DNS
  forward zones and `api.cloudflare.com`) cannot be blocked, unblocked or
  allowed via MCP. Matching is bidirectional (target, ancestors and
  descendants), case-insensitive and IDNA-aware.
- **Block-only rules.** MCP can create block rules only. There is no `action`
  field and no permanent allow: allows exist only through `allow_temporarily`
  with a mandatory expiry.
- **Mandatory expiry.** Every MCP-created block rule gets a server-set
  `expires_at` from `max_block_rule_lifetime`. Temporary allows and pauses are
  volatile and capped at one hour; expired rules are dropped at snapshot build.
- **Audit.** Every write tool records an audit entry (`action: "mcp.<tool>"`
  with actor, object, redacted before/after, result and error code). Read tools
  increment telemetry counters instead of per-call audit entries.
- **Transport hardening.** Bearer authentication, body caps, Origin checks,
  SEP-2243 header/body matching, per-token in-flight caps and a per-request
  deadline apply before or around tool dispatch.

## Manual interop recipe

The endpoint is stateless: there is no `initialize` handshake, no session
header and no cookies. Every request declares the protocol version in both the
`MCP-Protocol-Version` header and the request `_meta`, and carries
`Mcp-Method` (plus `Mcp-Name` for `tools/call`). Examples use documentation
names only.

**Automated coverage:** `cargo test -p dnscraft-mcp --test v2_surface` covers
classify/tracking gates, clarify errors, new writes, prompts, and resources.
OAuth multi-client: `cargo test -p dnscraft-api --lib api::oauth`. Live
connector matrix below is owner-run.

These curl steps need a running control-api with MCP enabled
(`public_url` set for remote clients) and either OAuth or a token with
`mcp:read`.

### Connector interop matrix (owner checklist)

Built-in redirect allowlist (no extras needed for these): Claude callbacks;
ChatGPT stable + `connector/oauth/{id}`; Cursor `localhost:8787` / agents /
`cursor://…`; Perplexity (+ Enterprise); VS Code loopback/web; any
`http://127.0.0.1|localhost` loopback. Set `public_url` for remote hosts.
AS advertises RFC 9207 `iss` support.

| Client | Auth | Register → Consent → `tools/list` → one read | Date / result |
|---|---|---|---|
| Claude (web / desktop connector) | OAuth DCR + browser consent | | not run |
| ChatGPT (custom MCP / plugins) | OAuth DCR; stable redirect via `iss` | | not run |
| Cursor (desktop / agents) | OAuth DCR or static bearer | | not run |
| Perplexity (custom connector) | OAuth; UI may ask for client secret — prefer DCR or static bearer | | not run |
| Loopback desktop (Claude Code, etc.) | OAuth loopback redirect | | not run |

1. Start the server with `[control_api.mcp] enabled = true`, optional
   `public_url = "https://dnscraft.example.net:8443"`, and a test token or
   admin browser session for OAuth.

2. List tools (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-read-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/list' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect `200 OK` with `application/json` and a `result.tools` array of 22
   read tools (36 with the write gate on).

3. Call `get_status` (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-read-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/call' \
     -H 'Mcp-Name: get_status' \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect a result whose `content[0].text` is a JSON document and whose
   `structuredContent` matches the node-status shape.

4. Call `add_rule` with a `mcp:write` token (not run):

   ```bash
   curl -sS https://dnscraft.example.net:8443/mcp/v1 \
     -H 'Authorization: Bearer <mcp-write-token>' \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'MCP-Protocol-Version: 2026-07-28' \
     -H 'Mcp-Method: tools/call' \
     -H 'Mcp-Name: add_rule' \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_rule","arguments":{"domain":"ads.example.com"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
   ```

   Expect a block rule with a server-set `expires_at`. Repeating with a
   `mcp:read` token returns `isError: true` and
   `control_api.auth.insufficient_scope`.

5. Negative check (not run): send `MCP-Protocol-Version: 2099-01-01` and expect
   `400` with JSON-RPC error `-32022`; send `GET /mcp/v1` and expect `405`.
