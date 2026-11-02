# Todo: web-ui extra features beyond the current specs (WX1–WX8)

> Specs: [`SPEC-web-ui.md`](../../docs/SPEC-web-ui.md) § Feature coverage (Extra features) and
> § Required control-api additions; [`SPEC-control-api.md`](../../docs/SPEC-control-api.md);
> [`SPEC-resolver.md`](../../docs/SPEC-resolver.md) § Upstream health / Cache.
> Related: [`todo-webui-api-gaps.md`](todo-webui-api-gaps.md) (OWNER item still open),
> [`todo-webui-prototype-gaps.md`](todo-webui-prototype-gaps.md).
> Archived 2026-11-02 — WX1–WX8 shipped. Log: [`progress.md`](../progress.md).

## WX1 — Befehlspalette (Cmd/Ctrl+K)

- [x] **WX1** Command palette, web-ui only, no backend. Done 2026-11-02.
  - [x] Phase 0: shortcut rule and domain-filter routing shipped with the palette.
  - [x] Phase 1: no backend crate.
  - [x] Phase 2: no control-api route; uses existing endpoints only.
  - [x] Phase 3: `CommandPalette` component. Vitest: `palette_filters_by_role`,
        `palette_hides_admin_items_for_viewer`, `palette_domain_maps_to_query_log_filter`,
        `palette_combobox_aria_attributes`, `palette_typed_text_not_sent_to_server`.
        Playwright: `palette_keyboard_only_flow`. Accessibility check of the open dialog.

## WX2 — Live-Mitschnitt Query-Log

- [x] **WX2** `GET /api/v1/query-log/stream` (SSE), owner `control-api`, role viewer/admin. Phases 0–3 done (counter `query_log.stream_dropped`, live tail in the query log).
  - [x] Phase 0: shipped as documented (no replay, node-local, 512-event queue,
        4 streams per principal / 32 per node, 30 min idle close).
  - [x] Phase 1: `dnscraft-api` fan-out over the query-log sink (non-blocking broadcast);
        new counter `query_log.stream_dropped`. Tests: `stream_applies_same_filters_as_list`,
        `stream_lagged_event_reports_dropped_count`, `stream_never_blocks_sink`,
        `stream_limit_returns_429`.
  - [x] Phase 2: route with cookie auth and bearer fetch auth; headers `no-store` and
        `X-Accel-Buffering: no`. Tests: `stream_viewer_allowed`,
        `stream_unauthenticated_401`, `stream_invalid_filter_400_before_open`,
        `stream_heartbeat_every_15s`, `stream_ignores_token_in_query_string`.
  - [x] Phase 3: live tail in `/query-log` (`query-log-stream.ts`), buffer and backoff reconnect.
        Vitest: `live_buffer_caps_rows`, `live_reconnect_backoff`. Playwright:
        `query_log_live_pause_resume`. CSP check: `connect-src 'self'` suffices.

## WX3 — Upstream-Gesundheit

- [x] **WX3** Upstream health, owner `resolver` (counters) and `control-api` (route). Phases 0–3 done.
  - [x] Phase 0: shipped as documented (aggregate recursion row, passive sampling,
        5 min window).
  - [x] Phase 1: `dnscraft-resolver` sampling ring and `Resolver::upstreams()`. Tests:
        `upstream_unknown_below_three_samples`, `upstream_down_when_success_below_half`,
        `upstream_samples_outside_window_ignored`, `upstream_last_error_is_stable_code`,
        `upstream_health_sends_no_probe_queries`.
  - [x] Done (2026-10-28, was deferred): DNSSEC Bogus results are counted as upstream failures
        (SPEC-resolver.md § Upstream health lists them). The verdict is per zone/answer and
        the answering target is unknown there; needs the responder address threaded out of
        `exchange_forward`. Test when done: `upstream_bogus_counts_as_failure`.
  - [x] Phase 2: `GET /api/v1/resolver/upstreams` in `dnscraft-api`. Tests:
        `upstreams_viewer_200`, `upstreams_unauthenticated_401`,
        `upstreams_without_forward_zones_returns_recursion_only`.
  - [x] Phase 3: upstream health on the dashboard (the separate `/statistics` route was
        retired). Vitest covers the dashboard upstream section.

## WX4 — Cache leeren

- [x] **WX4** `POST /api/v1/resolver/cache/flush`, owner `resolver` (return count) and
      `control-api` (route), role admin, audited. Phases 0–3 done.
  - [x] Phase 0: shipped as documented (node-local, subtree flush, empty body flushes all).
  - [x] Phase 1: `Resolver::flush` returns `FlushReport { evicted }`. Tests:
        `flush_all_reports_evicted_count`, `flush_domain_removes_subtree_only`,
        `flush_removes_stale_entries`, `flush_during_inflight_does_not_repopulate`
        (epoch guard), `flush_twice_is_noop_with_zero`.
  - [x] Phase 2: route in `dnscraft-api`, audit entry with `scope`, `domain`, `evicted`.
        Tests: `flush_admin_200_audited`, `flush_viewer_403`,
        `flush_invalid_domain_400`, `flush_empty_body_flushes_all`.
  - [x] Phase 3: cache flush sheet on the dashboard (`CacheSheet.svelte`).

## WX5 — Domain-Detail

- [x] **WX5** `GET /api/v1/stats/domains/{name}`, owner `control-api` over query log and
      statistics, role viewer/admin. Phases 0–3 done.
  - [x] Phase 0: shipped as documented (retention-bounded `first_seen`, daily series,
        10-client cap).
  - [x] Phase 1: aggregation over the raw query log and daily table. Tests:
        `domain_counts_7d_and_30d`, `domain_blocked_allowed_split`,
        `domain_top_clients_capped_at_10`, `domain_retention_limited_flag_set`,
        `domain_client_ip_truncated_per_setting`.
  - [x] Phase 2: route with name normalization. Tests: `domain_name_normalized_and_validated`,
        `domain_unseen_returns_404`, `domain_viewer_200`, `domain_days_only_7_or_30`.
  - [x] Phase 3: `/dashboard/domains/:name`, links from top-domains and the query log.

## WX6 — Konfig prüfen (Dry-run)

- [x] **WX6** `POST /api/v1/config/validate`, owner `control-api`, role admin. Phases 0–3 done.
  - [x] Phase 0: shipped as documented (no audit, no version bump, HTTP 200 with errors).
  - [x] Phase 1: reuse the module and cross-module validation without `apply_config`.
        Tests: `validate_does_not_bump_version`, `validate_never_calls_apply`,
        `validate_reports_errors_as_data_200`, `validate_diff_redacts_secrets`.
  - [x] Phase 2: route. Tests: `validate_viewer_403`, `validate_malformed_body_400`,
        `validate_if_match_conflict_reported_as_error`.
  - [x] Phase 3: validate-then-save on `/settings/config` (`config.test.ts`).

## WX7 — Benachrichtigungen (webhook / ntfy)

- [x] **WX7** `GET/PUT /api/v1/notifications` and `POST /api/v1/notifications/test`. Phases 0–3 done. Automatic dispatch is `dispatch_alerts` (webhook only; ntfy not in v1).
      owner `control-api` (delivery module in `dnscraft-api`), role viewer/admin read,
      admin write.
  - [x] Phase 0: owner decisions recorded in `docs/SPEC-control-api.md` (WX7 paragraph), 2026-10-28:
        (a) webhook only in v1, no ntfy/e-mail/push; (b) side by side with `tls.notifications`,
        migrate later; (c) ntfy not in v1; (d) `allowed_hosts` empty = reject all;
        (e) `allow_private_destinations` false.
  - [x] Phase 1: config section, egress guard and delivery. Tests:
        `egress_rejects_private_ranges_by_default`, `egress_pins_validated_address`,
        `egress_does_not_follow_redirects`, `egress_host_not_in_allowlist_422`,
        `payload_has_no_client_names_by_default`, `secret_redacted_on_get`,
        `secret_kept_when_omitted_on_put`, `secret_cleared_on_null`.
  - [x] Phase 2: routes. Tests: `notifications_put_creates_new_config_version`,
        `notifications_put_conflict_409`, `notifications_test_delivery_502_reason`,
        `notifications_test_audited`, `notifications_unknown_channel_404`,
        `notifications_viewer_read_only`.
  - [x] Phase 3: "Kanäle" section on `/alerts` (`ChannelsPanel.svelte`). Webhook only;
        ntfy stayed out of v1.

## WX8 — Aktive Sitzungen

- [x] **WX8** `GET /api/v1/auth/sessions` and `DELETE /api/v1/auth/sessions/{id}`, owner
      `control-api`, role viewer/admin (own), admin (all). Phases 0–3 done.
  - [x] Phase 0: shipped as documented (admin `scope=all`, truncated IP, parsed label,
        404 for a viewer's foreign id).
  - [x] Phase 1: session store changes: public `id` separate from the cookie value,
        truncated IP and label stored at login. Tests: `sessions_ip_truncated_at_write`,
        `sessions_user_agent_not_stored_raw`, `session_id_differs_from_cookie_value`.
  - [x] Phase 2: routes. Tests: `sessions_viewer_sees_own_only`, `sessions_admin_sees_all`,
        `sessions_viewer_scope_all_403`, `session_delete_current_409`,
        `session_viewer_foreign_id_404`, `session_admin_revokes_other_then_401`,
        `session_delete_requires_csrf_for_cookie`, `session_revoke_audited`.
  - [x] Phase 3: "Aktive Sitzungen" in `/settings` (`SessionsPanel.svelte`). Vitest:
        `sessions.test.ts`.

## Checkpoints

- [x] After WX1 and WX3 phase 3: palette and upstream section render with fixture data.
- [x] After WX2 phase 2: stream serves the same rows as the list for an identical filter.
- [x] After WX4 and WX6 phase 2: flush and validate routes covered by the RBAC matrix and
      audit tests.
- [x] After WX7 phase 0: all five owner decisions recorded; no egress code before that.
- [x] After WX8 phase 2: revoke-then-401 test green (`session_admin_revokes_other_then_401`).
