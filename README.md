# svc-peer

WireGuard control-plane hub + agent + owned relay for low-latency peer data (e.g. CCTV).

Greenfield Go (`github.com/betuah/svc-peer`). Inspired by Tailscale / Headscale / Netbird patterns — not a fork or vendor of those products.

## Architecture (locked MVP)

| Plane | Role |
|-------|------|
| **Hub** | REST + WebSocket: tokens, register, netmap, heartbeat, punch coordination, relay tickets |
| **Agent** | Kernel WireGuard preferred (`wgctrl`); **wireguard-go** fallback; STUN + hole punch; relay shim; MagicDNS from netmap |
| **Relay** | First-party fallback: opaque WG packet forward over **UDP** and **WS** (HMAC tickets) |

- Data plane is **direct agent↔agent** peers (not hairpin-only through the hub).
- **Agent ID** is created on **first successful register**; reconnect restores the same identity.
- Tokens: `POST /hub/tokens` (+ revoke/rotate) under `hub_secret`, and/or hub `pre_seed_tokens`.
- Overlay CIDR is configurable; no WebRTC primary path.

## Privileges

Creating a WireGuard / TUN interface requires **CAP_NET_ADMIN** (Linux) or equivalent admin rights:

```bash
# typical local smoke
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

2. Start camera agent (needs CAP_NET_ADMIN):

```bash
sudo go run ./cmd/agent -config configs/agent.example.yaml
```

3. Start viewer agent (different interface/port; pre-seeded token):

```bash
sudo go run ./cmd/agent -config configs/agent-viewer.example.yaml
```

4. Expect: both register → endpoint reports → punch candidates exchanged → WG peers configured.
   If direct handshake does not land within `direct_wait_sec`, agents request relay tickets and switch the peer endpoint to a local UDP shim (`127.0.0.1`) that wraps opaque WG packets to the relay.

5. Overlay reachability (once handshake succeeds):

```bash
# from host, ping viewer overlay IP shown in agent logs / GET /agents
ping 10.10.0.3   # example — use overlay_ip from register response
```

List agents:

```bash
curl -s -H "Authorization: Bearer spt_dev_cam_warehouse_01_replace_me" \
  http://127.0.0.1:8080/api/v1/agents | jq
```

## Layout

```
cmd/hub|agent|relay
internal/hub          tokens, registry/IPAM, REST, control WS, punch/tickets
internal/agent        hub client, path manager, STUN, punch, relay client
internal/agent/wgdev  kernel (linux) + userspace wireguard-go
internal/relay        UDP + WS forwarders (ticket auth)
internal/ticket       HMAC relay tickets (shared hub/relay secret)
internal/protocol     shared message types
configs/              example YAML
```

## What works vs remaining stubs

**Working**

- Real WG keygen; kernel (`wgctrl`+netlink) and userspace (`wireguard-go`) devices
- Netmap → `ConfigurePeers` / endpoint updates; handshake polling
- STUN srflx + host candidates; hub punch coordination; agent UDP probes
- Relay tickets (HMAC with `hub_secret` / `relay_secret`); UDP + WS opaque forward; local shim for WG
- MagicDNS map update from netmap; token/register/heartbeat unchanged

**Still stub / deferred**

- Full CCTV streaming profiles (SRT/RTSP over tunnel)
- Durable persistence (SQLite/Postgres), TLS everywhere, production ACL
- Non-Linux automatic overlay address assignment polish
- Rich path metrics / multi-relay selection

## Tests

```bash
go test ./...
```

## License

TBD
