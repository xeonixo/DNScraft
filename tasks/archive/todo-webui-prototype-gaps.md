# Todo: web-ui prototype placeholders awaiting backend (WP1–WP5)

> Spec: [`SPEC-web-ui.md`](../../docs/SPEC-web-ui.md). Prototype:
> [`web-ui-prototype.html`](../../docs/design/web-ui-prototype.html).
> Control-api gaps: [`todo-webui-api-gaps.md`](todo-webui-api-gaps.md).
> Archived 2026-11-02 — WP1–WP5 shipped. Log: [`progress.md`](../progress.md).

## Phase 0 — spec sign-off

Shipped 2026-11-02 with the proposed shapes (no separate owner rewrite): `GET /api/v1/alerts`,
`GET /api/v1/update/check` (opt-in, ~24 h cache), `GET /api/v1/backups` +
`PUT /api/v1/backups/settings`, runtime `services.json` with `available: false`, and
per-filter-set toggles on `GET`/`PUT /api/v1/filtering/services`.

- [x] **WP1** Alerts (`/alerts`): shipped as `GET /api/v1/alerts` (the proposed route).
- [x] **WP2** Update notice (`/settings` → Allgemein): `GET /api/v1/update/check`, opt-in, ~24 h cache.
- [x] **WP3** Automatic backups (`/settings` → Konfiguration): `GET /api/v1/backups` and
      `PUT /api/v1/backups/settings`.
- [x] **WP4** Blocked services catalog: runtime download of `services.json` +
      `services_i18n.json` (GPL-3.0, never bundled) and the `available: false` state.
- [x] **WP5** Blocked services toggle: per-filter-set on `GET`/`PUT /api/v1/filtering/services`.

## Phase 1 — backend

- [x] **WP1** Implement `GET /api/v1/alerts` in `control-api` (viewer/admin) aggregating
      TLS expiry, failed filter-list updates, cluster node offline and DynDNS failures,
      with `active_count` and `items[]` (`id`, `severity`, `module`, `params`, `target_route`).
      Tests: no alerts → empty list; cert within threshold → one item; viewer allowed.
- [x] **WP2** Implement `GET /api/v1/update/check` (built 2026-10-28, 0eaa305: opt-in, cached, tests `update_check_*`)
      — original spec: in `control-api` (viewer/admin): binary
      fetches the GitHub latest release, caches it, returns `update_available` and
      `release_url`; disabled or unreachable → `latest: null`. Tests: opt-out returns no
      outbound request; unreachable GitHub returns a coded error, not a 500.
- [x] **WP3** Implement `GET /api/v1/backups` (built 2026-10-28, 0eaa305: VACUUM INTO, retention; the binary must call `run_backup_if_due`)
      — original spec:  and `PUT /api/v1/backups/settings` in
      `control-api` (admin): last run, next run, directory, retention count. Tests:
      admin read/write; viewer `403`; invalid retention rejected.
- [x] **WP4** (filtering crate part done 2026-10-28; the route is WP5) Filtering crate: download, cache and back off `services.json` and
      `services_i18n.json` like a filter list, with `available` and `catalog_updated_at`.
      Tests: catalog absent → `available: false`; cached catalog loads offline.
- [x] **WP5** `control-api` (built 2026-10-28, c7aaa3a; the catalog provider is `ServiceCatalogProvider`, the assembler must implement it, until then `available: false`): `GET /api/v1/filtering/services` (viewer/admin) and
      `PUT /api/v1/filtering/services/{service_id}` (admin, `filter_set_id`, `enabled`);
      icons sanitized before serving. Tests: unknown id → `filtering.service.unknown`;
      catalog absent → `filtering.catalog.unavailable`; viewer → `403`.

## Phase 2 — web UI wiring

- [x] **WP1** `/alerts` grouped list, Übersicht badge and dashboard banner; empty state when
      `active_count` is 0.
- [x] **WP2** Allgemein update row with the "update available" row, release-notes link and
      opt-out switch; hidden when disabled.
- [x] **WP3** Konfiguration backup status and retention controls (admin only).
- [x] **WP4** `/blocked-services` shows unavailable when `available` is false.
- [x] **WP5** `/blocked-services` grouped catalog, names in the viewer locale, per-set toggles
      (admin only).

## Checkpoints

- [x] After WP1–WP3 (Phase 1): alerts, update check and backups endpoints served; RBAC matrix updated.
- [x] After WP4–WP5: `/blocked-services` lists the real catalog, or shows "unavailable"
      without one; icons are not returned by the API (no sanitizer path in the payload).
- [x] After Phase 2: product screens no longer use placeholders for WP1–WP5. The static
      prototype [`web-ui-prototype.html`](../../docs/design/web-ui-prototype.html) stays the
      design reference and is not rewritten here.
