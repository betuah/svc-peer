# svc-peer

svc-peer is a WireGuard overlay control and data-plane stack written in Go. It provides a multi-tenant overlay (`hub_id`) with exactly one **center** agent and many **edge** agents. Application traffic uses direct WireGuard between edge and center. The hub assists with NAT (STUN, relay, thin signaling) and is not the preferred path for application data.

The center agent (`role=center`) is the network authority for join tokens, allowlist sync, ACL, and membership. The main business application is a separate process that only consumes overlay IPs / MagicDNS.

## Binaries

| Binary | Package | Role |
|--------|---------|------|
| `hub` | `cmd/hub` | Thin control plane per `hub_id`: register, netmap fan-out, allowlist cache, punch/relay tickets |
| `agent` | `cmd/agent` | Center or edge peer: local `agent_id`, WireGuard device, hub client, local HTTP API |
| `relay` | `cmd/relay` | DERP-like forwarder for encrypted WireGuard packets when direct UDP fails |

## Roles

| Role | Cardinality | Dataplane peers |
|------|-------------|-----------------|
| center | Exactly one per `hub_id` | All edges |
| edge | Many | Center only (direct WG) |
| edge↔edge | — | Denied unless a center-authored grant adds a direct WG peer |
| hub | One process per deployment mode | Not an application next-hop |

## Deploy sketch

**Vendor cloud (default):** run `hub` + `relay` (and STUN) in the vendor cloud. Run the center agent on the customer site next to the main app (same host, separate process). Run edge agents on remote sites. App data prefers direct WG edge↔center; cloud carries signaling and relay fallback only.

**Self-host:** run `hub` + `relay` near the center agent on the customer site. Same binaries and ACL; no vendor cloud in path. Hub remains a distinct process from the center agent and from the main app.

## Join flow

1. Start hub (+ relay) with `hub_id` and shared `center_bootstrap`.
2. Start the center agent with matching `center_bootstrap` and `role: center`. It generates a local `agent_id`, registers, claims the sole center slot, loads durable allowlist state under `state_dir`, and syncs active edge join tokens via `PUT /hub/allowlist`.
3. Create or revoke edge join tokens on the center local API (`/local/allowlist`), or seed them with YAML `edge_tokens`. Start edge agents with those tokens (`role: edge`). Each edge persists its own `agent_id`. Netmap peers are center-only.
4. Direct WireGuard edge↔center. Path selection order for an allowed peer:
   **private/underlay host → STUN reflexive / hole punch → relay fallback**.
   Agents advertise host-local addresses (including RFC1918 / CGNAT) plus STUN
   candidates; the hub exchanges them for allowed pairs only (default edge↔center).
   Hub is signaling only — not the application dataplane next-hop.

## Hub durable state

Set `state_path` in the hub config (see `configs/hub.example.yaml`; Compose uses `/var/lib/svc-peer/hub-state.json`). The hub stores a JSON snapshot of the edge allowlist cache and registered agents so membership survives process restarts.

| Persisted | Not persisted |
|-----------|---------------|
| Edge allowlist (id, hash, label, tags, agent binding, revoked) | Online / offline presence |
| Agents (`agent_id`, role, name, WG pubkey, overlay IP, DNS name, token id, tags) | Heartbeat / last-seen / endpoints |

After restart, agents are offline until they register or heartbeat again; overlay IPs and token bindings are kept. Center remains the source of truth for edge tokens and re-syncs with `PUT /hub/allowlist` on connect. The hub file is a cache for NAT’d enrollment, not mint UX.

## Build

Requires Go 1.23.1 (see `go.mod`).

```bash
go build ./...
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay
```

Creating a WireGuard or TUN interface needs `CAP_NET_ADMIN` (or root):

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./bin/agent
```

## Run (local smoke)

Example configs live under `configs/`. Local examples use plain HTTP; leave `tls_cert_file` / `tls_key_file` empty.

```bash
go run ./cmd/hub -config configs/hub.example.yaml
go run ./cmd/relay -config configs/relay.example.yaml
sudo go run ./cmd/agent -config configs/agent-center.example.yaml
sudo go run ./cmd/agent -config configs/agent.example.yaml
```

Hub discovery:

```bash
curl -s -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  http://127.0.0.1:8080/api/v1/agents
```

## Hub TLS (HTTPS / WSS)

For cloud or self-host production, configure PEM paths on the hub so REST and control WebSocket are TLS:

| Knob | Process | Notes |
|------|---------|-------|
| `tls_cert_file` | hub | PEM certificate path; required with `tls_key_file` |
| `tls_key_file` | hub | PEM private key path; required with `tls_cert_file` |
| `hub_url` | agent | Use `https://…`; control channel upgrades to `wss://…/ws/v1/agent` |
| `hub_tls_insecure_skip_verify` | agent | Default `false`. Set `true` only for local/dev self-signed certs |

Both hub TLS paths must be set or both empty (empty = plain HTTP for local/dev). Compose: mount certs (see commented volume in `docker-compose.yml`) and set the paths in `configs/compose/hub.yaml`; point agent `hub_url` at `https://hub:8080`.

```bash
# Example: hub with TLS, agent verifying system roots (or skip-verify for self-signed)
# hub: tls_cert_file + tls_key_file set
# agent: hub_url: "https://127.0.0.1:8080"
curl -s --cacert /path/to/ca.pem \
  -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  https://127.0.0.1:8080/api/v1/agents
```

Center agent local API (default bind `127.0.0.1:9100`):

```bash
curl -s http://127.0.0.1:9100/local/health
curl -s http://127.0.0.1:9100/local/peers
curl -s http://127.0.0.1:9100/local/allowlist
curl -s -X POST http://127.0.0.1:9100/local/allowlist \
  -H 'Content-Type: application/json' \
  -d '{"label":"cam-01","tags":["warehouse"]}'
curl -s -X POST http://127.0.0.1:9100/local/allowlist/sync
```

Center join-token state is stored at `{state_dir}/allowlist.json` (for example `./state/center/allowlist.json`). The hub allowlist remains a cache; center re-syncs on connect and after local create/revoke.

## Docker images

One image per binary. Multi-stage builds; hub/relay use distroless, agent uses Alpine.

| Image tag | Dockerfile | Binary |
|-----------|------------|--------|
| `svc-peer-hub` | `Dockerfile.hub` | `hub` |
| `svc-peer-agent` | `Dockerfile.agent` | `agent` |
| `svc-peer-relay` | `Dockerfile.relay` | `relay` |

```bash
docker build -f Dockerfile.hub -t svc-peer-hub:local .
docker build -f Dockerfile.agent -t svc-peer-agent:local .
docker build -f Dockerfile.relay -t svc-peer-relay:local .
```

The agent container needs `CAP_NET_ADMIN` (and usually `CAP_NET_RAW`) plus `/dev/net/tun` for WireGuard. Kernel WG also requires the `wireguard` module on the host; compose examples set `wg_backend: userspace` so agents can run with a TUN device alone.

Mount a config file at `/etc/svc-peer/config.yaml` (image default `-config` path), or pass `-config` explicitly.

## Docker Compose

`docker-compose.yml` defines `hub` and `relay` by default. Center/edge agents are under the `agents` profile (TUN + capabilities).

Compose-oriented configs: `configs/compose/` (service DNS names `hub` / `relay`; local API bound on `0.0.0.0`).

```bash
# Control plane only
docker compose up -d --build

curl -s http://127.0.0.1:8080/health

# Hub + relay + center + edge (requires /dev/net/tun on the host)
docker compose --profile agents up -d --build

curl -s http://127.0.0.1:9100/local/health
curl -s http://127.0.0.1:9101/local/health
curl -s -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  http://127.0.0.1:8080/api/v1/agents
```

| Service | Host ports |
|---------|------------|
| hub | `8080` |
| relay | `3478/udp`, `3479` |
| agent-center | `51820/udp`, local API `9100` |
| agent-edge | `51821/udp`, local API `9101` |

Replace the example secrets in `configs/compose/*.yaml` before any shared or production use.

## Configuration

| File | Process |
|------|---------|
| `configs/hub.example.yaml` | Hub (`center_bootstrap`, overlay CIDR, `state_path`, optional TLS, STUN/relay URLs) |
| `configs/agent-center.example.yaml` | Center agent (`hub_url`, `center_bootstrap`, `edge_tokens`, `local_api_listen`) |
| `configs/agent.example.yaml` | Edge agent (`hub_url`, join token, `local_api_listen`) |
| `configs/agent-viewer.example.yaml` | Second edge example (different WG interface / local API port) |
| `configs/relay.example.yaml` | Relay |
| `configs/compose/*.yaml` | Compose service configs |

Agent `local_api_listen` defaults to `127.0.0.1:9100`. Set empty to disable. Use distinct ports when multiple agents share a host (viewer example uses `127.0.0.1:9101`).

## API reference

See [docs/api.md](docs/api.md) for hub control endpoints and agent local HTTP endpoints (methods, auth, fields).

## CI

GitHub Actions workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pull requests and pushes to `main`: `go vet`, `go build ./...`, `go test ./...`, and `go test -tags=integration ./test/integration/...` (Go 1.23.1).

## Layout

```
cmd/hub|agent|relay
internal/hub                 registry, allowlist, ACL netmap, HTTP + control WS
internal/agent               hub client, identity, path manager, WG backends
internal/agent/allowlist     center durable edge join-token store + hub sync
internal/agent/localapi      loopback /local/* HTTP API
internal/relay               UDP + WebSocket forwarders
configs/                     example YAML
configs/compose/             Compose service configs
docs/api.md                  HTTP API reference
Dockerfile.hub|agent|relay   per-binary images
docker-compose.yml           hub, relay, optional agents profile
.github/workflows/ci.yml     vet, build, unit + integration tests
test/integration/            integration tests (build tag integration)
```

## Tests

```bash
go test ./...
go test -tags=integration ./test/integration/...
```

Unit tests are colocated with packages. Integration tests live under `test/integration/` and require `-tags=integration`.

## License

TBD
