# Todo: Web-UI/API öffentlich erreichbar, im UI einstellbar, mit Fail2ban-Sperre (PW1–PW3)

> Archived 2026-11-02 — core shipped (opt-in public via shared DoH listener, bans, settings,
> `allowed_cidrs`). Deferred notes below stay open ideas, not a live task list.
> Spec: [`SPEC-control-api.md`](../../docs/SPEC-control-api.md). Log: [`progress.md`](../progress.md).

## Already there (reuse, don't rebuild)

- Per-source token-bucket limits: `crates/dnscraft-api/src/api/rate_limit.rs` (read/write/auth classes, LRU-bounded).
- Per-account and per-source login lockout (GA11): `api/auth/local.rs::authenticate_from`.
- Listener-side strike/ban for malformed DoH: `strike_malformed` in `doh.rs` (admission module).

## PW1 — Öffentlicher Web-Zugang (opt-in)

- [x] Phase 0 decisions, shipped as proposed: (a) default off, enabled per setting; (b) UI/API reachable on the shared
      public DoH listener only, never an own public socket; (c) sign-in stays required (login and OIDC are public,
      everything else needs a session as today); (d) TLS is the shared listener's; (e) optional `allowed_cidrs`
      (empty = no extra restriction; private sources always allowed). Done 2026-11-02.
- [x] `route()`: `WebSlot::set_public` / `set_public_cidrs`, `doh.rs` `web_allowed`. Private sources always;
      public sources only while public access is on, the peer matches the allowlist, and the peer is not banned.
      Hot-swappable (no restart).
- [x] Tests: `public_source_gets_web_handler_only_while_public_access_is_enabled`,
      `public_listener_routes_the_web_handler_for_private_sources_only`,
      `public_web_cidr_allowlist_filters_public_sources_only`.
- [x] Spec: SPEC-control-api success criterion 9 matches the opt-in shared-listener exception.
      There is no numbered README security row; `deploy/README.md` states the same rule.

## PW2 — Fail2ban-Sperre für Web-Zugriffe

Built by reusing the listeners' shared `BanTable` (`bans.rs`; thresholds from `public.ban_strikes/window/duration`,
default 5 strikes / 60 s / 15 min). Deviations from the first draft: the ban is **shared** with DNS
(a banned IP also loses DoH/DoT), is **in-memory only** (lost on restart), has no escalation, and
the unban has no audit row (tracing only). Add when needed.

- [x] `StrikeReason::WebAuth`: strike on failed `POST /api/v1/auth/local/login` (401/423/429) and on any 403
      from the web handler, public sources only. Plain 401s are not counted (SPA probes `/auth/me`).
- [x] Banned public sources never reach the web handler (`web_allowed` in `doh.rs`).
- [x] `GET /api/v1/web-bans`, `DELETE /api/v1/web-bans/{ip}` (admin) over `ListenerSet::banned_sources/unban`.
- [x] Tests: `failed_web_logins_from_a_public_source_ban_it_and_close_the_web_path`,
      `plain_401s_on_public_web_paths_do_not_ban`, `web_bans_list_sorted_and_unban`.
- [ ] Open: persistence across restart, escalating duration, audit row on unban, strikes for 404 scans / bearer failures,
      editing ban thresholds in the UI (today: listeners `public` config).

## PW3 — Einstellungen im UI

- [x] `GET/PUT /api/v1/web-access` (admin): `public_enabled` and optional `allowed_cidrs`, stored in
      `control_api_settings.web_access`, applied live via `ModuleAppliers.web` (boot, replace, cluster sync).
      `ban_*` stay in listeners public config (not this setting); see PW2 open items.
- [x] Web: `web/src/lib/settings/WebAccessPanel.svelte` — switch, CIDR textarea while public is on,
      banned-address list with unban. Ban thresholds are not edited here.
- [x] Lock-out guard: `PUT /web-access` with `public_enabled=true` refuses while
      `DNSCRAFT_ADMIN_PASSWORD_FILE` is set or neither OIDC nor a local account exists
      (`control_api.web_access.bootstrap_auth`, 2026-11-01).
- [ ] Gates still open: full `cargo clippy`, `pnpm check/lint`, Playwright toggle + unban, desktop/mobile/dark.
      CIDR behavior is covered by `cargo test -p dnscraft-listeners` / `dnscraft-api` web-access tests (2026-11-02).
