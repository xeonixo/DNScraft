# Todo: web-ui blocking control-api gaps (GA1–GA4, GA6)

> Archived 2026-11-02. Contract: [`plan-webui-api-gaps.md`](plan-webui-api-gaps.md).
> Gaps: [`todo-spec-gaps.md`](todo-spec-gaps.md) § control-api.
> Remaining open item: **OWNER** permanent block from the query log (below).
> Log: [`progress.md`](../progress.md).

## Phase 0 — auth/me + CSRF (GA1)

- [x] **GA1** `GET /api/v1/auth/me`: `auth_me` handler returning
      `{ role, actor_id, actor_type, csrf_token }` (D1); register `get(auth_me)` beside
      the other auth routes. RBAC already maps it to `Requirement::Api`.
      Tests: authenticated viewer/admin gets their role + a stable CSRF token matching
      `csrf::csrf_token_for`; unauthenticated → `401`.

## Phase 1 — token list + revoke (GA2, GA3)

- [x] **GA2** `GET /api/v1/auth/tokens`: `list_tokens` handler over
      `TokenStore::snapshot_entries()` → array of
      `{id, name, scope, actor_id, created_at, expires_at}` (D2, never plaintext);
      register `get(list_tokens)`. Tests: admin lists; viewer `403`; response contains
      no plaintext token.
- [x] **GA3** `DELETE /api/v1/auth/tokens/{id}`: `delete_token` handler over
      `TokenStore::revoke(id)` (D3); register `delete(delete_token)`. Tests: admin
      revokes → `200` + token stops authenticating; unknown id → `404
      auth.unknown_token`; viewer → `403`.

## Phase 2 — audit list (GA4)

- [x] **GA4** `GET /api/v1/audit`: `list_audit` handler over `Db::audit_list(limit,
      offset)` with defaulted + capped `limit`/`offset` (D4); register `get(list_audit)`.
      Tests: admin lists newest-first; viewer `403` (D4); redacted rows (no secret
      material); read failure maps to `control_api.audit.read` (GA22).

## Phase 3 — clients directory + sync (GA6)

- [x] **GA6a** `AppState::with_clients(Arc<ClientEngine>)` + accessor; `list_clients`
      returns `engine.lookup().clients()` mapped to the D5 DTO (falls back to the
      current manual-only/empty shape when no engine is wired). Tests: empty
      directory, manual-only, mixed UniFi+manual.
- [x] **GA6b** `sync_clients` calls `engine.sync_now()` → `SyncReport`, mapping
      errors to `clients.*` codes; keeps `clients.sync.not_configured` when no engine.
      Tests: sync success + report, sync error mapping, no engine → `not_configured`.
- [x] **GA6c** Binary wiring: the assembler hands the built `ClientEngine` to
      `AppState::with_clients` (reuses the `EngineClients` already built for the query
      log). Done 2026-10-28: `EngineDirectory` + `control_api.rs` `with_clients`;
      smoke asserts `/clients`.

## Checkpoints

- [x] After GA1: `cargo test -p dnscraft-api` green; `auth/me` returns role + CSRF.
- [x] After GA1–GA3: token CRUD e2e (create → list → revoke → 401).
- [x] After GA1–GA4: auth + audit routes served; RBAC matrix green.
- [x] After GA6: `GET /clients` returns the real directory; `POST /clients/sync`
      returns a report (or `not_configured` without UniFi); assembler boots.

## Found while building the SPA login (W4, 2026-10-28)

- [x] **GA-W4a** OIDC callback (`api/auth/oidc.rs`) returns a JSON envelope; it must redirect back to the SPA
      (validated same-origin `return_to`), otherwise the browser login ends on a JSON page.
- [x] **GA-W4b** `authorize-url` accepts no `return_to`; add it (same-origin path only, validated server-side).
- [x] **GA-W4c** Public auth routes ignore + clear a stale cookie; logout is Public so expired
      sessions still get `Max-Age=0` (2026-11-01).
- [x] **GA-W4d** CSRF is body-field only (`auth/me` / login → `X-CSRF-Token`); SPEC-web-ui Q2 resolved.
- [x] **GA-W4e** `429` envelopes include `params.retry_after` (header kept).

## Found while building the dashboard (W5, 2026-10-28)

- [x] **GA-W5a** `stats/overview` includes `response_time_ms: { p50, p95 }` from raw timings (null on rollup).
- [x] **GA-W5b** `GET /stats/top_blocked_domains` routed.
- [x] **GA-W5c** `GET /filtering/pause?filter_set_id=` returns `{ filter_set_id, paused_until }`.
- [x] **GA-W5d** `resolver.*` / `upstream.*` codes added to web error catalogue + en/de messages.
- [x] **GA-W5e** SPEC-web-ui: dashboard owns stats; runtime pause via `/filtering/pause`; `/statistics` retired.
- [x] **GA-W5f** `GET /stats/timeseries?bucket=hour|day` returns `{ bucket_start, total, blocked }` rows.

## Found while building the query log (W6, 2026-10-28)

- [x] **GA-W6a** Records include `status`; filter accepts `cache` (resolve step source).
- [x] **GA-W6b** List response includes `query_log_dropped` and `query_log_stream_dropped`.
- [x] **GA-W6c** List response includes `total`; filter accepts `query_type` (subnet already existed).
- [x] **GA-W6d** `mcp.*` write/validation codes in web error catalogue + en/de messages.
- [x] **OWNER** "Dauerhaft blockieren" from the log: **shipped**. Query-log RuleSheet
      permanent allow/block writes `custom_rules` via `PUT /api/v1/filter-sets` (no
      MCP lifetime cap). `max_block_rule_lifetime` applies only to MCP
      `add_custom_rule` / `mcp_rules`.

## Found while building policy/clients/filter screens (W8, 2026-10-28)

- [x] **GA-W8a** Documented 2026-11-02: RBAC stays admin-only for config-family GETs
      (`roles.rs` `is_config_path`). SPEC-web-ui route table and `web/src/lib/nav.ts`
      `minRole` match that. Viewers keep dashboard, query log, alerts, blocked services,
      test query and settings. `/rules` is admin because it reads filter sets.
- [x] **GA-W8b** Documented: no `GET /policy/profiles`. `listProfiles` reads
      `policy.profiles` from `GET /api/v1/config` (`profilesFromConfig`).
- [x] **GA-W8c** Documented: `ForwardZone` is `id`, `zone`, `targets`, `validate`. Reverse-zone
      and a per-zone profile allow-list are not resolver fields. Profile `forward_zones`
      is a separate policy allow-list and is not edited on `/forward-zones`.
- [x] **GA-W8d** Documented: no filter-list refresh endpoint. The UI footnote says lists
      update on the configured interval only.
- [x] **GA-W8e** Documented: CNAME uncloaking is always-on policy behavior, not a filter-set
      field and not a UI toggle.

## Found while building listeners/TLS/cluster/settings (W9, 2026-10-28)

- [x] **GA-W9a** Documented 2026-11-02: bootstrap `[control_api.mcp]` on `ControlApiConfig`
      and versioned `control_api_settings.mcp` (`enabled`, `write_tools_enabled`,
      `legacy_session_mode`). Stored booleans overlay TOML at process start; a restart
      is required. Limits stay bootstrap-only. See SPEC-control-api.
- [x] **GA-W9b** `DELETE /api/v1/filtering/temporary-allows` (`domain`, optional `filter_set_id`).
- [x] **GA-W9c** Deferred: no per-listener rate-limit field in `listener_routes.rs`. Global
      `rate_per_source` and `rate_per_client_id` stay in listener limits. Noted in SPEC-web-ui.
- [x] **GA-W9d** `query_log.ip_truncate` is bootstrap-only; not editable via `/config` (UI shows read-only note).
      Done: `control_api_settings.query_log.ip_truncate` (and `retention_days`) is in the versioned snapshot and applied live to `QueryLog` on boot, `PUT /config`, rollback and cluster sync; default is now `none`.
