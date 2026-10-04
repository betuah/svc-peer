# Deploy guide

This guide covers running svc-peer in **vendor cloud** (default) and **self-host** modes, colocating the center agent with the main app, placing edge agents, TLS for the hub control plane, Docker Compose, and WireGuard capability requirements.

For product topology and ACL/identity decisions, see [architecture.md](./architecture.md). For HTTP endpoints, see [api.md](./api.md).

## Prerequisites

- Go 1.23.1 (native builds; see `go.mod`)
- Linux hosts for agents (Windows / embedded supported by design; compose examples assume Linux + `/dev/net/tun`)
- For kernel WireGuard: `wireguard` kernel module on the agent host
- For userspace WireGuard: TUN device access (`/dev/net/tun`) and `CAP_NET_ADMIN` (usually also `CAP_NET_RAW`)
- Replace all example secrets in `configs/` and `configs/compose/` before shared or production use

## Deploy modes

### Vendor cloud (default)

Run **hub + relay** (and STUN, or point `stun_urls` at a reachable STUN service) in the vendor cloud. Run the **center agent** on the customer site next to the main application (same host, **separate process**). Run **edge agents** on remote sites.

| Plane | Location |
|-------|----------|
| Signaling / allowlist cache / break-glass | Vendor hub |
| Relay fallback | Vendor relay |
| Network authority (tokens, ACL, membership) | Center agent on customer host |
| App dataplane | Direct WG edge↔center; cloud is not the preferred next-hop |

Cloud does not mint day-to-day edge tokens, does not own policy, and does not carry preferred application media.

### Self-host

Run **hub + relay** on the customer site near (or on the same LAN as) the center agent. Same binaries, ACL, and identity model; no vendor cloud in the path. Hub remains a distinct process from the center agent and from the main app.

## Process placement

| Process | Placement |
|---------|-----------|
| `hub` | Vendor cloud **or** customer site (self-host). Never inside the main app. |
| `relay` | Same site as hub (cloud or self-host). |
| `agent` `role=center` | Customer host with the main app; separate process/container. |
| Main app | Overlay consumer only (binds/connects via overlay IP / MagicDNS). |
| `agent` `role=edge` | Remote sites; optional edge apps are consumers only. |

**Invariant:** hub ≠ center agent ≠ main app.

Recommended bring-up order:

1. Start hub (with `hub_id`, `center_bootstrap`, overlay CIDR, `state_path`, STUN/relay URLs).
2. Start relay (shared `relay_secret` with hub).
3. Start center agent (`role: center`, matching `center_bootstrap`); it registers, claims the sole center slot, loads durable join-token state from `{state_dir}/allowlist.json` (optional YAML `edge_tokens` seed), and syncs active tokens via `PUT /hub/allowlist`.
4. Create or revoke edge join tokens on the center local API (`/local/allowlist`), or rely on seeded YAML tokens. Start edge agents with those tokens (`role: edge`).
5. Confirm direct WireGuard edge↔center; relay is used only if underlay/STUN/punch fails.

Path selection for an allowed peer: **private/underlay host → STUN reflexive / hole punch → relay fallback**.

Center remains the source of truth for edge join tokens. The hub allowlist is a cache for NAT’d enrollment; the center re-syncs on connect and after local create/revoke (`POST /local/allowlist/sync` forces a full push).

## TLS certificates (hub control plane)

Production cloud and self-host deployments should terminate TLS on the hub for REST and the agent control WebSocket.

| Knob | Process | Notes |
|------|---------|-------|
| `tls_cert_file` | hub | PEM certificate; required together with `tls_key_file` |
| `tls_key_file` | hub | PEM private key; required together with `tls_cert_file` |
| `hub_url` | agent | Use `https://…`; control channel upgrades to `wss://…/ws/v1/agent` |
| `hub_tls_insecure_skip_verify` | agent | Default `false`. Set `true` only for local/dev self-signed certs |

Both hub TLS paths must be set, or both empty (empty = plain HTTP for local/dev). Example knobs live in `configs/hub.example.yaml` and agent examples.

Compose: mount certs (commented volume in `docker-compose.yml`) and set paths in `configs/compose/hub.yaml`; point agent `hub_url` at `https://hub:8080`.

```bash
# Hub with TLS; agent verifies system roots (or use --cacert / skip-verify for self-signed)
curl -s --cacert /path/to/ca.pem \
  -H "Authorization: Bearer <edge-join-token>" \
  https://hub.example:8080/api/v1/agents
```

Relay `hub_url` should match the hub scheme when the hub serves HTTPS.

## Native build and capabilities

```bash
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay
```

Creating a WireGuard or TUN interface needs `CAP_NET_ADMIN` (or root):

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./bin/agent
```

| Backend | Requirement |
|---------|-------------|
| `wg_backend: kernel` (or `auto` when module present) | `wireguard` module + netlink / `CAP_NET_ADMIN` |
| `wg_backend: userspace` | `/dev/net/tun` + `CAP_NET_ADMIN` (compose examples use this) |

Do not run the agent without the capability required for the chosen backend; registration may succeed while the dataplane interface fails to create.

Local smoke (plain HTTP; leave TLS paths empty):

```bash
go run ./cmd/hub -config configs/hub.example.yaml
go run ./cmd/relay -config configs/relay.example.yaml
sudo go run ./cmd/agent -config configs/agent-center.example.yaml
sudo go run ./cmd/agent -config configs/agent.example.yaml
```

## Docker images

One image per binary. Hub/relay use distroless; agent uses Alpine.

```bash
docker build -f Dockerfile.hub -t svc-peer-hub:local .
docker build -f Dockerfile.agent -t svc-peer-agent:local .
docker build -f Dockerfile.relay -t svc-peer-relay:local .
```

Mount config at `/etc/svc-peer/config.yaml` (image default `-config` path), or pass `-config` explicitly.

Agent containers need `CAP_NET_ADMIN` (and usually `CAP_NET_RAW`) plus `/dev/net/tun`. Kernel WG also needs the host `wireguard` module; compose examples set `wg_backend: userspace` so agents can run with a TUN device alone.

## Docker Compose

`docker-compose.yml` defines `hub` and `relay` by default. Center/edge agents are under the `agents` profile (TUN + capabilities). Compose configs live under `configs/compose/` (service DNS names `hub` / `relay`; local API bound on `0.0.0.0` for container access).

```bash
# Control plane only
docker compose up -d --build
curl -s http://127.0.0.1:8080/health

# Hub + relay + center + edge (requires /dev/net/tun on the host)
docker compose --profile agents up -d --build
curl -s http://127.0.0.1:9100/local/health
curl -s http://127.0.0.1:9101/local/health
```

| Service | Host ports |
|---------|------------|
| hub | `8080` |
| relay | `3478/udp`, `3479` |
| agent-center | `51820/udp`, local API `9100` |
| agent-edge | `51821/udp`, local API `9101` |

Hub durable state: set `state_path` (Compose uses `/var/lib/svc-peer/hub-state.json`). The hub persists edge allowlist cache and registered agents; online presence is not persisted. Center remains the source of truth for edge tokens and re-syncs with `PUT /hub/allowlist` on connect.

### Suggested production Compose adjustments

- Replace example `center_bootstrap`, `management_token_seed`, `relay_secret`, and edge tokens.
- Enable hub TLS (`tls_cert_file` / `tls_key_file`) and switch agent `hub_url` to `https://…`.
- Persist agent `state_dir` volumes so `agent_id` and WG keys survive restarts.
- Expose hub/relay publicly as needed; keep agent local APIs on loopback or a private network unless intentionally exposed.
- Prefer kernel WG on bare-metal/VM agents when the module is available; keep userspace for constrained containers.

## Configuration map

| File | Process |
|------|---------|
| `configs/hub.example.yaml` | Hub (`center_bootstrap`, overlay CIDR, `state_path`, optional TLS, STUN/relay URLs) |
| `configs/agent-center.example.yaml` | Center (`hub_url`, `center_bootstrap`, `edge_tokens`, `local_api_listen`) |
| `configs/agent.example.yaml` | Edge (`hub_url`, join token, `local_api_listen`) |
| `configs/agent-viewer.example.yaml` | Second edge example |
| `configs/relay.example.yaml` | Relay (`relay_secret`, listen addrs) |
| `configs/compose/*.yaml` | Compose service configs |

Agent `local_api_listen` defaults to `127.0.0.1:9100`. Set empty to disable. Use distinct ports when multiple agents share a host.

## Security checklist

- Treat `center_bootstrap` and join tokens as secrets; rotate if leaked before center claim.
- Use hub TLS in any non-local deployment; do not leave `hub_tls_insecure_skip_verify: true` outside lab use.
- Keep network management off the main app process.
- Scope all credentials and Agent IDs to one `hub_id`.
- Grant extra A2A peers only via center-authored grants (direct WG); never rely on hub hairpin for denied pairs.
