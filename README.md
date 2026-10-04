# svc-peer

WireGuard overlay: **one center** (business authority + main app) + many **edge** agents per `hub_id`. Happy-path app data is **direct WG edge↔center**. Cloud hub is a **NAT bridge** (STUN + relay + thin signaling) — not the app dataplane next-hop, not day-to-day token mint.

Greenfield Go (`github.com/betuah/svc-peer`). Inspired by Tailscale / Headscale / Netbird patterns — not a fork.

## Roles & ACL

| Role | Cardinality | Dataplane peers |
|------|-------------|-----------------|
| **center** | Exactly one per `hub_id` | All edges |
| **edge** | Many | **Center only** (direct WG) |
| edge↔edge | — | **Deny** (no peer, no hairpin) |
| hub | NAT bridge | **Not** app next-hop |

## Join flow (as implemented)

1. Start thin hub (+ relay) with `hub_id` + shared `center_bootstrap`.
2. Start **center** agent with the same `center_bootstrap` and `role: center`.
   - Generates/persists local `agent_id` under `state_dir`
   - Registers with bootstrap → claims sole center
   - Syncs `edge_tokens` to hub via `PUT /hub/allowlist`
3. Start **edge** agents with join tokens from center (`role: edge`).
   - Each generates/persists its own local `agent_id`
   - Registers with join token; hub rejects `agent_id` collisions
   - Netmap peers = **[center]** only
4. Direct WG edge↔center; STUN/punch/relay assist when NAT blocks UDP.

## Auth & API

`Authorization: Bearer <credential>`

| Credential | Use |
|------------|-----|
| **`center_bootstrap`** | Center first register + allowlist sync + center session |
| **Edge join token** | Edge register / heartbeat / netmap (created on center, synced to hub) |
| **Management token** | Break-glass revoke/mint/ops only — not primary onboarding |

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| PUT | `/hub/allowlist` | center_bootstrap | Sync edge join tokens from center |
| POST | `/hub/tokens` | management | Break-glass mint |
| DELETE | `/hub/tokens/{id}` | center or management | Revoke |
| POST | `/api/v1/agents/register` | bootstrap or join token | Present local `agent_id` + role |
| GET | `/api/v1/agents` | center/edge session | Discovery + online + role |
| GET | `/api/v1/netmap` | center/edge session | ACL peers (edge↔center) |
| GET | `/health` | none | Includes `hub_id`, `center_agent_id` |

## Privileges

Creating a WireGuard / TUN interface needs **CAP_NET_ADMIN** (or run as root).

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ./bin/agent
```

## Build

```bash
go build ./...
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay
```

## Smoke-test

```bash
go run ./cmd/hub -config configs/hub.example.yaml
go run ./cmd/relay -config configs/relay.example.yaml
sudo go run ./cmd/agent -config configs/agent-center.example.yaml
sudo go run ./cmd/agent -config configs/agent.example.yaml
sudo go run ./cmd/agent -config configs/agent-viewer.example.yaml
```

List agents (edge token or center bootstrap):

```bash
curl -s -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  http://127.0.0.1:8080/api/v1/agents | jq
```

## Layout

```
cmd/hub|agent|relay
internal/hub          thin NAT bridge: registry, allowlist, ACL netmap, punch/tickets
internal/agent        hub client, local identity, path manager, WG
internal/agent/identity  local agent_id persist
internal/relay        UDP + WS forwarders
configs/              hub, center, edge examples
test/integration/     integration tests (build tag integration)
```

## Tests

```bash
go test ./...
go test -tags=integration ./test/integration/...
```

## Remaining gaps

- Center process does not yet host a full policy UI (config-file edge tokens + allowlist sync for MVP)
- Grant TTL / durable persistence
- Optional hub WG for ops only (explicitly non-default)

## License

TBD
