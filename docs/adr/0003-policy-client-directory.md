# ADR-0003: Policy does not depend on dnscraft-clients

- Status: Accepted
- Date: 2026-10-25
- Deciders: recorded at map / plan level (CAPABILITY-MAP; policy plan cross-module decisions)
- Scope: `crates/dnscraft-policy` ↔ `crates/dnscraft-clients` ↔ `dnscraft-api` / `dnscraft` binary

## Context

Policy must answer local device names and PTRs using data that ultimately comes from UniFi /
manual client records (`dnscraft-clients`). Putting a Cargo dependency from `policy` onto
`clients` would pull UniFi HTTP/TLS types into the DNS hot-path crate and invert the build order
(`clients` is parallel to `resolver`/`filtering`/`tls`; `policy` sits above resolver+filtering).

## Decision

Define a **`ClientDirectory` trait in `dnscraft-policy`** with policy-owned types
(`addresses` / `reverse` / `local_domains`). `dnscraft-policy` must **not** take a Cargo
dependency on `dnscraft-clients`. The `dnscraft` binary adapts `ClientEngine` /
`ClientLookup` to `dyn ClientDirectory` for policy and to
`dnscraft_api::ClientDirectory` for REST/MCP (`EngineDirectory`). DoH/DoT **Client IDs**
remain separate from UniFi client records.

Recorded in [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md) ("Decisions recorded at map level") and
[SPEC-policy.md](../SPEC-policy.md) (objective / ClientDirectory integration). First
implementation: commit `58d5f52` (policy: P5 ClientDirectory names/PTR, 2026-10-25).

## Consequences

- Policy tests use `NoClients` or a stub directory; no UniFi mocks in the policy crate.
- The binary owns the adapters (`EngineDirectory` for the API/MCP client list including
  `last_seen`; a thin policy-side wrapper for local names/PTR). `dnscraft-api` does not
  depend on `dnscraft-clients` directly.
- Changing the trait is a cross-module change (policy + binary adapter + API DTO).

## Alternatives considered

- **Direct `dnscraft-clients` dependency from policy:** rejected in CAPABILITY-MAP / SPEC-policy
  ("Never: depend on `dnscraft-clients` directly").
- **Trait living in a third shared crate:** not chosen; rationale for preferring policy-local
  trait over a shared crate is **rationale not recorded** beyond "policy-owned types" in the
  spec/plan.

## Links

- [CAPABILITY-MAP.md](../../CAPABILITY-MAP.md)
- [SPEC-policy.md](../SPEC-policy.md) — ClientDirectory integration
- Commit `58d5f52` (policy: P5)
