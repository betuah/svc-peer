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
2. Start the center agent with matching `center_bootstrap` and `role: center`. It generates a local `agent_id`, registers, claims the sole center slot, and syncs `edge_tokens` via `PUT /hub/allowlist`.
3. Start edge agents with join tokens from the center (`role: edge`). Each persists its own `agent_id`. Netmap peers are center-only.
4. Direct WireGuard edge↔center; STUN/punch/relay when NAT blocks UDP.

## Build

Requires Go 1.23+.

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

Example configs live under `configs/`.

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

Center agent local API (default bind `127.0.0.1:9100`):

```bash
curl -s http://127.0.0.1:9100/local/health
curl -s http://127.0.0.1:9100/local/peers
```

## Configuration

| File | Process |
|------|---------|
| `configs/hub.example.yaml` | Hub (`center_bootstrap`, overlay CIDR, STUN/relay URLs) |
| `configs/agent-center.example.yaml` | Center agent (`center_bootstrap`, `edge_tokens`, `local_api_listen`) |
| `configs/agent.example.yaml` | Edge agent (join token, `local_api_listen`) |
| `configs/agent-viewer.example.yaml` | Second edge example (different WG interface / local API port) |
| `configs/relay.example.yaml` | Relay |

Agent `local_api_listen` defaults to `127.0.0.1:9100`. Set empty to disable. Use distinct ports when multiple agents share a host (viewer example uses `127.0.0.1:9101`).

## API reference

See [docs/api.md](docs/api.md) for hub control endpoints and agent local HTTP endpoints (methods, auth, fields).

Architecture and locked product decisions: project store docs (`wireguard-architecture-plan.md`, `project-context.md`) when working in the svc-peer project context.

## Layout

```
cmd/hub|agent|relay
internal/hub                 registry, allowlist, ACL netmap, HTTP + control WS
internal/agent               hub client, identity, path manager, WG backends
internal/agent/localapi      loopback /local/* HTTP API
internal/relay               UDP + WebSocket forwarders
configs/                     example YAML
docs/api.md                  HTTP API reference
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
