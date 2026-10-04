# svc-peer

WireGuard control-plane hub + agent + owned relay for low-latency peer data (e.g. CCTV).

Greenfield Go (`github.com/betuah/svc-peer`). Inspired by Tailscale / Headscale / Netbird patterns — not a fork or vendor of those products.

## Architecture (locked MVP)

| Plane | Role |
|-------|------|
| **Hub** | REST + WebSocket: management/agent tokens, register, ACL netmap, heartbeat, punch coordination, relay tickets |
| **Agent** | Kernel WireGuard preferred (`wgctrl`); **wireguard-go** fallback; STUN + hole punch; relay shim; MagicDNS from netmap |
| **Relay** | First-party fallback: opaque WG packet forward over **UDP** and **WS** (HMAC tickets) |

- **Multi-hub isolation:** each hub process has a `hub_id`; tokens/agents/netmaps are scoped to that hub; no cross-hub overlay.
- **Default ACL (hub-spoke):** Agent→Hub allow; Hub→agents allow; Agent→Agent **drop** (no peer, **no hairpin**).
- **A2A grant:** management token adds **direct WG** peers A↔B; hub is not in that media path.
- **Agent ID** is created on **first successful register**; reconnect restores the same identity.
- Auth is fully **token-based**: management token vs agent token (no separate `hub_secret` auth).
- Overlay CIDR is configurable; no WebRTC primary path; no custom streaming stack on WG.

## Auth & API

All protected routes use `Authorization: Bearer <token>`.

| Token | Capabilities |
|-------|----------------|
| **Management** | Mint/revoke/rotate agent tokens; grant/revoke A2A; list grants. Bootstrap via `management_token_seed` in hub config. |
| **Agent** | Register, heartbeat, `GET /agents`, `GET /netmap`, control WS. **Cannot** mint tokens or grant peers. |

### Management (hub ops)

```bash
# Mint agent token
curl -s -X POST http://127.0.0.1:8080/hub/tokens \
  -H "Authorization: Bearer change-me-management-token" \
  -H "Content-Type: application/json" \
  -d '{"label":"cam-02","tags":["camera"]}'

# Revoke / rotate
curl -s -X DELETE http://127.0.0.1:8080/hub/tokens/{id} \
  -H "Authorization: Bearer change-me-management-token"
curl -s -X POST http://127.0.0.1:8080/hub/tokens/{id}/rotate \
  -H "Authorization: Bearer change-me-management-token"

# Grant / revoke / list A2A (direct WG peers)
curl -s -X POST http://127.0.0.1:8080/hub/grants \
  -H "Authorization: Bearer change-me-management-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_a_id":"<uuid>","agent_b_id":"<uuid>"}'
curl -s http://127.0.0.1:8080/hub/grants \
  -H "Authorization: Bearer change-me-management-token"
curl -s -X DELETE http://127.0.0.1:8080/hub/grants/{grant_id} \
  -H "Authorization: Bearer change-me-management-token"
```

### Agent-facing (`/api/v1`)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/api/v1/agents/register` | agent | Returns `hub_id`, overlay IP, ACL-derived `peers` (default: hub only) |
| GET | `/api/v1/agents` | agent | Hub-scoped discovery + `online` status |
| GET | `/api/v1/agents/{id}` | agent | Detail on this hub |
| GET | `/api/v1/netmap` | agent | ACL-derived peers + MagicDNS map |
| GET | `/health` | none | Includes `hub_id` |
| WS | `/ws/v1/agent` | agent (hello) | Heartbeat, endpoint report, netmap push, punch, relay tickets |

`relay_secret` in hub/relay config is **only** for HMAC relay tickets — not an auth credential.

## Privileges

Creating a WireGuard / TUN interface requires **CAP_NET_ADMIN** (Linux) or equivalent admin rights:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./bin/agent
# or
sudo ./bin/agent -config configs/agent.example.yaml
```

Kernel backend also needs the `wireguard` kernel module. If unavailable, the agent falls back to userspace (`wireguard-go`).

## Build

```bash
go build ./...
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay
```

## Smoke-test two agents

1. Start hub + relay:

```bash
go run ./cmd/hub -config configs/hub.example.yaml
go run ./cmd/relay -config configs/relay.example.yaml
```

2. Start camera + viewer agents (needs CAP_NET_ADMIN), using pre-seeded agent tokens from hub config.

3. Default: each agent netmap peers **hub only**. To enable direct A2A:

```bash
# after both agents registered, grant with management token
curl -s -X POST http://127.0.0.1:8080/hub/grants \
  -H "Authorization: Bearer change-me-management-token" \
  -H "Content-Type: application/json" \
  -d '{"agent_a_id":"<cam>","agent_b_id":"<viewer>"}'
```

4. List agents (online/offline):

```bash
curl -s -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  http://127.0.0.1:8080/api/v1/agents | jq
```

## Layout

```
cmd/hub|agent|relay
internal/hub          tokens (mgmt/agent), ACL grants, registry/IPAM, REST, control WS
internal/agent        hub client, path manager, STUN, punch, relay client
internal/agent/wgdev  kernel (linux) + userspace wireguard-go
internal/relay        UDP + WS forwarders (ticket auth)
internal/ticket       HMAC relay tickets (shared hub/relay secret)
internal/protocol     shared message types
configs/              example YAML
test/integration/     integration tests (build tag integration)
```

## What works vs remaining stubs

**Working**

- Multi-hub isolation via `hub_id`-scoped tokens/agents/netmaps
- Management vs agent token roles; bootstrap `management_token_seed`
- Default hub-spoke ACL netmap; A2A grants → direct WG peers; no hairpin
- Real WG keygen; kernel (`wgctrl`+netlink) and userspace (`wireguard-go`) devices
- STUN srflx + host candidates; punch for **granted** peers; ticketed relay
- MagicDNS map from netmap (resolution ≠ dataplane permission)

**Still stub / deferred**

- Hub process running its own WG dataplane device (agents already get hub peer in netmap)
- Full CCTV streaming profiles (SRT/RTSP over tunnel)
- Durable persistence (SQLite/Postgres), TLS everywhere
- Grant TTL/sessions; multi-tenant many hubs in one process

## Tests

Unit tests live next to packages; integration/smoke tests live under `test/integration/` (build tag). Details: [test/README.md](./test/README.md).

```bash
# Unit only (default)
go test ./...

# Integration / control-plane smoke
go test -tags=integration ./test/integration/...
```

## License

TBD
