# Deploying DNScraft (Docker)

Container delivery for the [`dnscraft`](../crates/dnscraft/) binary.

- Sample configs: [`dnscraft.docker.toml`](dnscraft.docker.toml) (image and compose default) and [`dnscraft.example.toml`](dnscraft.example.toml) (local loopback dev).
- Project overview and non-Docker quick start: [root README](../README.md).
- Binary behaviour (control API, MCP, cluster): [`crates/dnscraft/README.md`](../crates/dnscraft/README.md).

> **Note:** the container sample binds `0.0.0.0` and therefore sets `control_api.allow_wildcard_bind = true`. Without that flag the control API only accepts loopback, private or ULA addresses. Never enable it on a host with a public interface; publish the port deliberately (compose maps it to loopback).

## Quick start (compose)

From the repository root:

```bash
docker compose up --build
curl -fsS http://127.0.0.1:80/healthz
dig @127.0.0.1 -p 5300 example.com A +short
```

Data persists in the `dnscraft-data` volume (mounted at `data_dir = /var/lib/dnscraft`).

## Images

| File | Runtime | Notes |
|------|---------|-------|
| [`Dockerfile`](../Dockerfile) | Debian bookworm-slim (glibc), runs as uid `10001` | **Default.** Embeds the web UI (`--features web-ui`). Includes `curl` for the `HEALTHCHECK`. |
| [`Dockerfile.musl`](../Dockerfile.musl) | `scratch` + static musl binary, runs as root | Experimental. No shell, no `curl`, no `HEALTHCHECK`, no web UI. Use orchestrator probes. |

Base images are pinned by digest in both Dockerfiles, and GitHub Actions in the workflows are pinned to commit SHAs.

### Releases

Pushing a tag `vX.Y.Z` runs [`release.yml`](../.github/workflows/release.yml). The tag must equal the `dnscraft` crate version, or the workflow fails. It builds the glibc image for `linux/amd64` and `linux/arm64` on native runners in parallel, pushes it to `ghcr.io/xeonixo/dnscraft` as `X.Y.Z` and `X.Y` (plus `latest` for stable releases), and creates a GitHub Release. Tags containing a `-` (for example `v0.2.0-rc.1`) become pre-releases and do not move `latest` or `X.Y`.

```bash
# bump version in crates/*/Cargo.toml, commit, then:
git tag v0.1.0 && git push origin v0.1.0
docker pull ghcr.io/xeonixo/dnscraft:0.1.0
```

### Why glibc is the default

The workspace targets glibc Linux in CI. The musl static build needs the Alpine toolchain in `Dockerfile.musl` and is not wired into CI yet. `rusqlite` uses the bundled SQLite amalgamation, and `ring` links on both glibc and musl when built in the musl builder stage.

## Build

Single platform:

```bash
docker build -t dnscraft:local -f Dockerfile .
docker build -t dnscraft:musl -f Dockerfile.musl .
```

Multi-arch needs [Docker Buildx](https://docs.docker.com/build/building/multi-platform/). A multi-platform build cannot be loaded into the local daemon, so push to a registry:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile \
  -t ghcr.io/<owner>/dnscraft:latest \
  --push \
  .
```

`Dockerfile.musl` maps `TARGETARCH` to `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` and installs the target with `rustup` in the build stage. Use the same `buildx --push` form for it.

## Run without compose

```bash
docker build -t dnscraft:local .
docker run --rm \
  -p 5300:5300/udp -p 5300:5300/tcp -p 127.0.0.1:80:80/tcp \
  -v dnscraft-data:/var/lib/dnscraft \
  -v "$PWD/deploy/dnscraft.docker.toml:/etc/dnscraft/config.toml:ro" \
  dnscraft:local
```

Musl image (config path is `/config/config.toml`):

```bash
docker build -t dnscraft:musl -f Dockerfile.musl .
docker run --rm -v "$PWD/deploy/dnscraft.docker.toml:/config/config.toml:ro" \
  -v dnscraft-data:/var/lib/dnscraft -p 5300:5300/udp -p 5300:5300/tcp \
  dnscraft:musl
```

## Secrets (never in the image)

Supply secrets at runtime through environment variables or `*_FILE` paths (Docker secrets or mounted PEM files). The binary rejects conflicting duplicate sources.

| Variable | Purpose |
|----------|---------|
| `DNSCRAFT_TLS_CERT` / `DNSCRAFT_TLS_CERT_FILE` | PEM chain for DoT/DoH/DoQ listeners |
| `DNSCRAFT_TLS_KEY` / `DNSCRAFT_TLS_KEY_FILE` | PEM private key |
| `DNSCRAFT_OIDC_CLIENT_SECRET` / `*_FILE` | OIDC client secret (control-api auth) |
| `DNSCRAFT_ADMIN_PASSWORD_FILE` | Seeds the local `break-glass` admin on a fresh install (only while no local account exists) |
| `DNSCRAFT_UNIFI_API_KEY` / `*_FILE` | UniFi integration |
| `DNSCRAFT_CLOUDFLARE_API_TOKEN` / `*_FILE` | ACME DNS-01 (see `dnscraft-tls`) |
| `DNSCRAFT_CLUSTER_JOIN_TOKEN` / `*_FILE` | Sub-node enrollment |
| `DNSCRAFT_CLUSTER_MASTER_CERT_FILE` | Pinned master certificate (PEM) |

Operator-provided TLS material is loaded from the variables above. When `[tls]` ACME is configured, the engine manages certificates itself.

## Ports

Docker sample (`dnscraft.docker.toml`):

| Port | Protocol | Service |
|------|----------|---------|
| 5300 | UDP, TCP | Plain DNS listeners on `0.0.0.0:5300` |
| 80 | TCP | Control API, plain HTTP (`tls = false`): `/healthz`, `/readyz`, REST, optional MCP |
| 443 | TCP (and UDP for HTTP/3) | Public encrypted DNS, e.g. DoH; also the shared web UI/API port if `shared_doh_listener` is set |

Compose publishes the control API as `127.0.0.1:80` only. Port 443 is published as `443:443/tcp`. Publish every other listener port you enable, such as DoT on 853 or DoQ on UDP.

Local dev without Docker uses [`dnscraft.example.toml`](dnscraft.example.toml): DNS on `127.0.0.1:5300` and no `[control_api]` section, so binary defaults apply. Those defaults are `bind = 127.0.0.1`, `port = 443` and `tls = true` (self-signed bootstrap certificate). To serve plain HTTP on 8080, add a `[control_api]` block with `port = 8080` and `tls = false`.

Public encrypted listeners (`192.0.2.1`, `example.com`) stay commented in `dnscraft.example.toml`. Enable them only with real certificates and domains you control.

### Source classification & proxies

DNScraft classifies a client as private or public from the **TCP peer address** it sees. Docker's userland proxy, NAT, and reverse proxies replace the real client address with the proxy's, so every client can look private. In that case:

- an open DoH listener accepts queries without a Client ID,
- the web UI is reachable from outside, and
- no source is banned.

The control API logs a warning at startup when it shares a DoH listener. To keep real source IPs, use host networking (`network_mode: host`) or iptables-based publishing (the default `docker-proxy` path does not preserve them). Put the web UI behind TLS and authentication either way.

## Production checklist

- [ ] **TLS and auth before publishing 443.** Configure `DNSCRAFT_TLS_*` or `[tls]` ACME, and do not expose the control API as plain HTTP.
- [ ] **Public web access stays off.** It is off by default. Enable it only on purpose, through the web-access setting (`/api/v1/web-access`, stored as `control_api_settings.web_access.public_enabled`).
- [ ] **Break-glass admin.** Set `DNSCRAFT_ADMIN_PASSWORD_FILE` for the first boot to seed the `break-glass` admin. Create your normal accounts, then remove the variable and file. Existing accounts are never overwritten.
- [ ] **Reverse proxy.** Set `control_api.trusted_proxies` to the proxy's address. The proxy must send `X-Forwarded-For` and `X-Forwarded-Proto`, which are honoured only from trusted proxies. Remember that source classification still uses the TCP peer, so a proxy on a private network makes all clients look private.
- [ ] **Public DoH.** Public DoH listeners need Client IDs (`<id>.dns.<domain>` or `/dns-query/<id>`). Do not run an open DoH listener on a public address.
- [ ] **HTTP/3.** For DoH over HTTP/3, publish UDP 443 as well (`443:443/udp`). Compose currently publishes only TCP 443.
- [ ] **Volumes and permissions.** The image runs as uid `10001` and owns `/var/lib/dnscraft`. Named volumes inherit this ownership. For a bind mount, make the host directory writable by uid `10001`. The musl image runs as root.
- [ ] **Health checks.** Confirm `/healthz` and `/readyz` return 200 after startup. Use the in-container `HEALTHCHECK` (glibc) or an external probe (musl).

## Health checks

- **Glibc image:** `HEALTHCHECK` in `Dockerfile` and compose calls `http://127.0.0.1:80/healthz` from inside the container. Publish `127.0.0.1:80:80` for host access.
- **Musl/scratch:** no in-image health check. Use compose or Kubernetes HTTP probes against a published control-API port, or run the glibc image.
