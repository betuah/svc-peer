# svc-peer

WireGuard control-plane hub + agent + owned relay for low-latency peer data (e.g. CCTV).

Greenfield Go (`github.com/betuah/svc-peer`). Inspired by Tailscale / Headscale / Netbird patterns — not a fork or vendor of those products.

## Architecture (locked MVP)

| Plane | Role |
|-------|------|
| **Hub** | REST + WebSocket control plane: tokens, register, netmap, heartbeat |
| **Agent** | Registers with hub; prefers **kernel WireGuard**, falls back to **wireguard-go**; MagicDNS resolve local from netmap |
| **Relay** | First-party fallback: forward opaque WG packets over **UDP** and **WS/TLS** |

- Data plane is **direct agent↔agent** peers (not hairpin-only through the hub).
- **Agent ID** is created on **first successful register**; reconnect with the same token restores the same identity.
- Tokens: `POST /hub/tokens` (+ revoke/rotate) protected by `hub_secret`, and/or hub config `pre_seed_tokens`; token goes in agent config.
- Overlay CIDR is configurable; no WebRTC primary path.

Design detail: see project docs (`wireguard-architecture-plan.md`).

## Layout

```
cmd/hub          Hub binary
cmd/agent        Agent binary
cmd/relay        Relay binary
internal/hub     Token store, registry/IPAM, REST, control WS, netmap
internal/agent   Config, hub client, WG device interface, MagicDNS
internal/relay   UDP forwarder + WS relay stub
internal/protocol Shared API / WS message types
configs/         Example YAML for hub, agent, relay
```

## Build

```bash
go build ./...
# or individual binaries:
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay
```

## Run (local scaffold)

Terminal 1 — hub:

```bash
go run ./cmd/hub -config configs/hub.example.yaml
```

Terminal 2 — relay:

```bash
go run ./cmd/relay -config configs/relay.example.yaml
```

Terminal 3 — agent (uses pre-seeded token from hub example config):

```bash
go run ./cmd/agent -config configs/agent.example.yaml
```

Mint an additional token (hub secret from config):

```bash
curl -s -X POST http://127.0.0.1:8080/hub/tokens \
  -H "Authorization: Bearer change-me-hub-secret" \
  -H "Content-Type: application/json" \
  -d '{"label":"viewer-02"}'
```

Health:

```bash
curl -s http://127.0.0.1:8080/health
```

## What works vs stub

**Implemented (scaffold / early Phase 1):**

- Hub HTTP: `/health`, `POST /hub/tokens`, `DELETE /hub/tokens/{id}`, `POST /hub/tokens/{id}/rotate`
- Hub agent API: `POST /api/v1/agents/register`, `GET /api/v1/agents`, `GET /api/v1/agents/{id}`, `GET /api/v1/netmap`
- Token bind on first register; reconnect same Agent ID; heartbeat online/offline (+ timeout sweep)
- In-memory token store + registry/IPAM from `overlay_cidr`; config pre-seed tokens
- Control WebSocket `/ws/v1/agent` (hello, heartbeat, endpoint_report stub, netmap push)
- Agent: config load, register, heartbeat WS client, MagicDNS map update, WG `Device` interface
- Relay: UDP announce/forward skeleton + WS `/relay` stub

**Stub / TODO:**

- Real kernel WG (`wgctrl`) and `wireguard-go` TUN bring-up
- STUN discovery, coordinated hole punch, relay ticket auth
- Durable persistence (file/SQLite), TLS everywhere, production ACL

## Tests

```bash
go test ./...
```

## License

TBD
