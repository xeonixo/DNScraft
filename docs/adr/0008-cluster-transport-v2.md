# ADR-0008: Cluster transport v2 (Prefer-QUIC, compression, reverse tunnel)

- Status: Accepted
- Date: 2026-11-02
- Deciders: project owner
- Scope: `crates/dnscraft-cluster`, cluster listener on the master, control-api cluster contract

## Context

Cluster v1 uses a single long-lived **HTTP/2** session over TLS 1.3 mTLS on port **8443**,
with NDJSON downstream on `GET /cluster/v1/stream` and uncompressed upstream batches. That
works on loopback and private networks but leaves bandwidth and operator reachability on the
table: sub-nodes are outbound-only, so the master cannot open diagnostics or admin actions
toward a node without the node first connecting.

Industry patterns for similar constraints:

- **Cloudflare Tunnel (`cloudflared`)** — `auto` transport tries QUIC first and falls back to
  TCP/HTTP/2 when UDP or QUIC is blocked ([Cloudflare docs: tunnel run parameters](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/cloudflared-parameters/run-parameters/)).
- **Kubernetes Konnectivity** — agents dial out; the apiserver multiplexes control traffic over
  the agent-initiated tunnel ([KEP-1281](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/1281-network-proxy)).
- **Teleport** — reverse tunnels over mutually authenticated agent sessions for SSH/Kubernetes
  access without inbound agent ports ([Teleport architecture](https://goteleport.com/docs/architecture/)).

DNScraft must stay **ring-only** (ADR-0002), **hub-and-spoke** (no multi-master), **no external
coordination services**, and **outbound-only from sub-nodes**. Operators still need transport
efficiency (compression on large snapshots and log batches) and master-initiated, allowlisted
access to a sub-node's loopback control-api for status and maintenance.

## Decision

1. **Protocol version 2** on the wire, negotiated in the first stream record. The master
   continues to accept **protocol 1** peers (HTTP/2 only, no `compress=zstd`, no reverse RPC
   multiplex). A v2 sub-node that cannot agree on v2 falls back to v1 behaviour or fails
   closed per `cluster.protocol.version` (SPEC-cluster.md).
2. **Prefer-QUIC dual stack (`auto`).** Default transport mode is **`auto`**: attempt
   **QUIC / HTTP/3** (UDP) on the cluster listen port, then **mandatory fallback** to
   **TCP + TLS 1.3 + HTTP/2** on the **same port** when QUIC handshake or path fails
   (cloudflared-style). Operators may pin `h2_only` for debugging. **0-RTT is disabled**
   on QUIC (no early data; replay risk unacceptable on an admin channel).
3. **Default cluster listen port `443`** (was `8443`). Still bound only to loopback or
   private/ULA addresses — never `0.0.0.0`/`::` on the public internet. The master serves
   **UDP and TCP on the same port** (QUIC + h2). `master_url` for sub-nodes uses that port.
   When a DoH listener already covers that `IP:port` (or
   `cluster.listen.share_with_listener` names one), the control plane **colocates** on the
   DoH socket via **SNI mux** (cluster `server_name` → cluster CA mTLS; other SNIs → ACME
   DoH) plus path dispatch (`/cluster/v1/*` vs `/dns-query`). Path-only sharing without SNI
   separation is not sufficient: DoH uses `with_no_client_auth()`, cluster needs handshake
   mTLS. A single `quinn` endpoint on UDP/443 demuxes DoH-h3 and Cluster-h3 the same way.
   **Note:** rustls only surfaces **DNS** SNIs to `ClientHello::server_name`; an IP SNI
   (common when `master_url` is an address literal) appears as `None`. When the cluster
   SNI is itself an IP, the mux therefore treats a missing SNI as cluster.
4. **zstd compression (v2 only).** When both sides advertise `capabilities` including
   `compress=zstd`, request bodies for cluster log (and other large) `POST`s **must** be
   sent as a `ZstdEnvelope` (or negotiated Content-Encoding) and decompressed before
   validate/ingest. Enforce a **decompressed size cap** per message and a
   **compression window ≤ 8 MiB**. Peers without the capability send and receive plaintext
   (v1-compatible). Settings `compression.enabled` must wire into the client; advertising
   the capability without compressing is a bug.
5. **Reverse tunnel over the sub-initiated session.** On v2, the same mTLS session
   multiplexes **master→sub typed RPCs** and an allowlisted **HTTP CONNECT** proxy to the
   sub-node's **loopback control-api only** (read-oriented admin proxy sketch in
   SPEC-control-api.md). Typed RPCs (initial set): `node.status`, `node.diagnostics`,
   `config.reapply`, `runtime.exec`. No arbitrary TCP port forward; CONNECT targets are
   fixed to loopback control-api bind (host/port from local bootstrap, not from RPC payload).
6. **Node-local cluster settings API.** Transport preference, compression toggle, and reverse-RPC
   policy are **not** replicated in the fleet config snapshot. They are stored per node and
   exposed as `GET/PUT /api/v1/cluster/settings` (master and sub-nodes; sub-node writes are
   local-only). UI: `/cluster` (SPEC-web-ui.md).
7. **Crypto stack unchanged.** QUIC via **quinn + rustls ring provider** only; no aws-lc,
   no 0-RTT, no third-party tunnel SaaS.

## Consequences

- Sub-nodes behind UDP-blocking firewalls still connect via h2 fallback without a separate
  port or operator workflow.
- Large config snapshots and log batches consume less bandwidth when zstd is active; memory
  bounds must be tested (decompress caps, window limit).
- Master admins can trigger diagnostics and read-only proxy flows without opening inbound
  ports on sub-nodes; misuse surface is limited by RPC allowlist and CONNECT target allowlist.
- Protocol 1 implementations remain valid; mixed fleets during rollout must be observable via
  `protocol_version`, `active_transport`, and `fallback_reason` on node status (SPEC-control-api.md).
- Default port **443** shared with DoH on the same private bind is **colocation** (SNI +
  path mux), not a configuration error. Distinct non-DoH listeners on the same address
  remain a collision.

## Alternatives considered

- **HTTP/2 only (status quo):** rejected — no compression, no reverse operations, sub-optimal
  on high-latency links; kept as protocol 1 compatibility path.
- **Separate QUIC port from TCP:** rejected — operator burden and firewall rules; same-port
  dual stack matches Cloudflare `auto` ergonomics.
- **General port forwarding (SSH-style):** rejected — expands blast radius; CONNECT limited
  to loopback control-api.
- **External tunnel broker (WireGuard mesh SaaS, etc.):** rejected — violates no external
  services and outbound-only product boundary.

## Links

- [SPEC-cluster.md](../SPEC-cluster.md) — transport, reverse tunnel, settings
- [SPEC-control-api.md](../SPEC-control-api.md) — § Cluster contract
- [ADR-0002](0002-ring-only-crypto.md) — rustls/quinn ring-only
- Cloudflare Tunnel — QUIC with HTTP/2 fallback (`auto`)
- Kubernetes Konnectivity — outbound agent tunnels
- Teleport — reverse tunnel over authenticated agent sessions
