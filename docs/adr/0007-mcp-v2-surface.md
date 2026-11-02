# ADR-0007: MCP v2 safe resources, multi-client OAuth, ads/tracker gate

- Status: Accepted
- Date: 2026-11-02
- Deciders: project owner
- Scope: `crates/dnscraft-mcp`, `crates/dnscraft-api` OAuth + MCP backend

## Context

MCP v1 was tools-only with a Claude-oriented OAuth thin layer. Product goals for
v2 require (1) diagnose / home-network / ops assistants, (2) connector OAuth
without pasted tokens for Claude, ChatGPT, Cursor and similar clients,
(3) clarify-first behaviour, and (4) refusing default allows for advertising and
tracker domains.

## Decision

1. **Safe resources and prompts.** Advertise `resources` and `prompts` with
   server-authored catalogs only (`dnscraft://status|alerts|filter-lists|policy/map`
   and static workflow prompts). Query-log content stays tool-only JSON so
   attacker-influenced names never become freeform prompt text.
2. **Multi-client OAuth.** Keep public-client PKCE DCR. Accept Claude callbacks,
   loopback, and owner `oauth_extra_redirect_uris`. Prefer `public_url` for
   discovery. Issue short-lived access tokens plus refresh tokens; consent
   selects `mcp:read` / `mcp:write`. Persist DCR when `oauth_clients_path` is set.
   Do not become a general IdP.
3. **Ads/tracker soft-gate.** `classify_domain` uses `TrackerDb` with the same
   tracking/functional map as the web UI. `allow_temporarily` /
   `propose_exception` refuse `kind=tracking` unless `acknowledge_tracking: true`.

## Consequences

- Assistants get richer inventory without REST parity for secrets or full config.
- New MCP clients can be onboarded via config extras without a code release.
- Tracking overrides remain possible but explicit and audited.
