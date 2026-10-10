# svc-peer HTTP API reference

This document describes the APIs implemented in the repository today.

- **Hub** (`cmd/hub`): control-plane HTTP(S) + agent WebSocket (WS/WSS). Auth uses `Authorization: Bearer <credential>`.
- **Agent local API** (`cmd/agent`): loopback HTTP on the agent process. No bearer auth (bind to loopback by default).

Error responses use JSON `{"error":"<message>"}` unless noted.

When hub `tls_cert_file` and `tls_key_file` are set, the hub serves **HTTPS**; agents should use `hub_url` with `https://` (control channel is **WSS**). Plain HTTP remains available when both TLS paths are empty (local/dev). TLS knobs, Compose cert mounts, and ports: [deploy.md](./deploy.md). Architecture overview: [architecture.md](./architecture.md).

---

## Credentials (hub)

| Credential | Config / source | Allowed operations |
|------------|-----------------|--------------------|
| `center_bootstrap` | Hub + center agent config (shared secret) | Center register; allowlist sync; center session for agents/netmap; revoke token; grants |
| Edge join token | Created/configured on center; synced to hub allowlist | Edge register; edge session for agents/netmap; control WS |
| Management token | Hub `management_token_seed` (break-glass) | Mint/rotate tokens; revoke; grants |

`center_bootstrap` is not an edge join token. Edges must not send it.

---

## Hub: health and metrics

### `GET /health`

| | |
|--|--|
| Auth | None |
| Response | `200` |

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` |
| `hub_id` | string | Hub tenant id |
| `center_agent_id` | string | Sole center agent id, if registered |
| `agents_connected` | int | Online agent count |
| `netmap_revision` | uint64 | Current netmap revision |

### `GET /metrics`

Prometheus text exposition (`text/plain; version=0.0.4`). Bound on hub `listen_addr` (same listener as `/health`). No auth — restrict with network policy in production.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `svc_peer_hub_http_requests_total` | counter | `method`, `path`, `status` | HTTP requests (chi route patterns) |
| `svc_peer_hub_http_request_duration_seconds` | histogram | `method`, `path` | Request latency |
| `svc_peer_hub_agents_registered` | gauge | `hub_id` | Registered agents |
| `svc_peer_hub_agents_online` | gauge | `hub_id` | Online agents |
| `svc_peer_hub_allowlist_size` | gauge | `hub_id` | Active edge allowlist entries |
| `svc_peer_hub_grants` | gauge | `hub_id` | Active A2A grants |
| `svc_peer_hub_ws_connections` | gauge | `hub_id` | Control WebSocket connections |

---

## Hub: registration and discovery

### `POST /api/v1/agents/register`

Present a locally generated `agent_id` and WireGuard public key.

| | |
|--|--|
| Auth | `center_bootstrap` (center) or edge join token (edge) |
| Request body | JSON |
| Response | `200` on success; `401` / `409` / `400` on failure |

**Request fields**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | yes | Locally generated; persisted on the agent |
| `name` | string | yes | Display name |
| `public_key` | string | yes | WireGuard public key (base64) |
| `role` | string | no | `center` or `edge`; must match credential |
| `tags` | string[] | no | Labels |
| `capabilities` | string[] | no | Capability tags |
| `platform` | string | no | e.g. `linux/amd64` |
| `wg_backend` | string | no | `kernel` / `userspace` / `auto` |

**Response fields**

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | string | Echo of presented id |
| `hub_id` | string | Hub tenant |
| `role` | string | `center` or `edge` |
| `center_agent_id` | string | Sole center id |
| `overlay_ip` | string | Assigned overlay prefix (e.g. `10.10.0.2/32`) |
| `dns_name` | string | MagicDNS name |
| `netmap_revision` | uint64 | Revision of returned peers |
| `peers` | PeerConfig[] | ACL peer list for this agent |
| `dns_map` | object | name → overlay IP |
| `stun_urls` | string[] | STUN servers |
| `relay_urls` | string[] | Relay URLs |

**PeerConfig**

| Field | Type | Description |
|-------|------|-------------|
| `peer_id` | string | Peer agent id |
| `agent_id` | string | Same as `peer_id` when set |
| `role` | string | `center` or `edge` |
| `public_key` | string | Peer WG public key |
| `endpoint` | string | UDP endpoint if known |
| `allowed_ips` | string[] | Overlay routes for the peer |
| `dns_name` | string | Peer MagicDNS name |
| `persistent_keepalive` | int | Seconds; optional |

Center register with `center_bootstrap` claims the sole center for `hub_id`. A second center claim returns `409`. Edge token already bound to a different `agent_id` returns `409`.

### `GET /api/v1/agents`

| | |
|--|--|
| Auth | Center session (`center_bootstrap` after center registered) or edge join token bound to an agent |
| Query | `online=true` — only online agents |
| Response | `200` |

| Field | Type | Description |
|-------|------|-------------|
| `hub_id` | string | Hub tenant |
| `center_agent_id` | string | Sole center id |
| `agents` | AgentSummary[] | Registered agents |

**AgentSummary**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Agent id |
| `name` | string | Display name |
| `role` | string | `center` or `edge` |
| `overlay_ip` | string | Overlay address (no prefix length) |
| `dns_name` | string | MagicDNS name |
| `tags` | string[] | Optional |
| `capabilities` | string[] | Optional |
| `online` | bool | Presence from heartbeat / WS |
| `last_seen` | string | RFC3339 timestamp |

### `GET /api/v1/agents/{id}`

| | |
|--|--|
| Auth | Same as list |
| Response | `200` AgentSummary; `404` if missing |

### `GET /api/v1/netmap`

| | |
|--|--|
| Auth | Same as list |
| Response | `200` netmap for the authenticated agent |

| Field | Type | Description |
|-------|------|-------------|
| `revision` | uint64 | Netmap revision |
| `center_agent_id` | string | Sole center id |
| `peers` | PeerConfig[] | Peers allowed by ACL |
| `dns_map` | object | name → overlay IP |

Default ACL: edges receive only the center; center receives all edges. Hub is not included as an app dataplane peer.

---

## Hub: center allowlist and tokens

### `PUT /hub/allowlist`

Primary path for edge onboarding: center pushes join tokens to the hub cache. Center remains the source of truth; the hub persists the allowlist (token hashes, not plaintext) under `state_path` so NAT’d enrollment can continue across hub restarts. On center connect/online, the center agent re-syncs this endpoint. Online presence is never taken from disk.

| | |
|--|--|
| Auth | `center_bootstrap` (center must already be registered, including restored from durable state) |
| Request body | JSON |
| Response | `200` |

**Request**

| Field | Type | Description |
|-------|------|-------------|
| `tokens` | AllowlistToken[] | Edge join tokens |

**AllowlistToken**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Optional stable id |
| `token` | string | Secret join token |
| `label` | string | Optional label |
| `tags` | string[] | Optional tags |

**Response**

| Field | Type | Description |
|-------|------|-------------|
| `hub_id` | string | Hub tenant |
| `upserted` | int | Count upserted |
| `ids` | string[] | Token record ids |

### `POST /hub/tokens`

Break-glass mint (management only). Not the primary onboarding UX.

| | |
|--|--|
| Auth | Management token |
| Request | `{ "label"?: string, "tags"?: string[] }` |
| Response | `201` TokenInfo including `token` secret |

### `DELETE /hub/tokens/{id}`

| | |
|--|--|
| Auth | `center_bootstrap` or management token |
| Response | `200` `{ "status":"revoked", "id":"..." }` |

### `POST /hub/tokens/{id}/rotate`

| | |
|--|--|
| Auth | Management token |
| Response | `200` `{ "id", "token", "agent_id"? }` |

---

## Hub: grants (extra A2A)

Center-authored grants add direct WireGuard peers beyond the default edge↔center ACL. Management token is accepted as break-glass.

### `POST /hub/grants`

| | |
|--|--|
| Auth | `center_bootstrap` or management |
| Request | `{ "id"?: string, "agent_a_id": string, "agent_b_id": string }` |
| Response | `201` GrantInfo (first create); `200` when the same `id`+pair already exists (idempotent re-sync) |

Optional `id` is supplied by the center so durable local grants keep a stable identity across hub restarts. Empty `id` generates a new UUID.

### `GET /hub/grants`

| | |
|--|--|
| Auth | `center_bootstrap` or management |
| Response | `{ "hub_id", "grants": GrantInfo[] }` |

### `DELETE /hub/grants/{id}`

| | |
|--|--|
| Auth | `center_bootstrap` or management |
| Response | `200` `{ "status":"revoked", "id":"..." }` |

**GrantInfo:** `id`, `hub_id`, `agent_a_id`, `agent_b_id`, `created_at`.

Hub grant state is an in-memory cache applied to netmap / punch / relay. The center persists grants under `{state_dir}/grants.json` and re-syncs on connect (`POST /hub/grants` + `DELETE` for local revokes).

---

## Hub: control WebSocket

### `GET /ws/v1/agent`

Agent control channel (gorilla WebSocket). Over plain HTTP the URL is `ws://…/ws/v1/agent`; over hub TLS it is `wss://…/ws/v1/agent` (agents derive this from `hub_url` `http`/`https`). First message is `hello` with `agent_id`, `hub_id`, and `token` (bootstrap or join token). Subsequent messages use the envelope types in `internal/protocol/messages.go`:

| Direction | `type` | Purpose |
|-----------|--------|---------|
| agent→hub | `hello` | Authenticate session |
| agent→hub | `heartbeat` | Presence |
| agent→hub | `endpoint_report` | Host-local (private underlay + other) and STUN `srflx` candidates, ranked underlay-first |
| agent→hub | `path_status` | `direct` / `relay` for a peer |
| agent→hub | `relay_request` | Request relay ticket |
| hub→agent | `netmap` | Peer list + DNS map push |
| hub→agent | `punch` | Hole-punch candidates |
| hub→agent | `relay_ticket` | Relay auth ticket + URLs |
| hub→agent | `error` | Error code/message |

---

## Agent local HTTP API

Served by the **agent** process (`role=center` or `role=edge`), not the hub. Bind address: config `local_api_listen` (default `127.0.0.1:9100`). Empty disables the server (including metrics).

No authentication. Intended for loopback / host-local tooling only.

### `GET /metrics`

Prometheus text on `local_api_listen`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `svc_peer_agent_local_api_requests_total` | counter | `method`, `path`, `status` | Local API requests |
| `svc_peer_agent_local_api_request_duration_seconds` | histogram | `method`, `path` | Local API latency |
| `svc_peer_agent_peers` | gauge | `hub_id`, `agent_id`, `role` | Netmap peer count |
| `svc_peer_agent_wg_handshake_age_seconds` | gauge | `hub_id`, `agent_id`, `peer_id` | Seconds since last WG handshake (`-1` if none) |
| `svc_peer_agent_wg_tx_bytes` | gauge | `hub_id`, `agent_id`, `peer_id` | WG device TX bytes |
| `svc_peer_agent_wg_rx_bytes` | gauge | `hub_id`, `agent_id`, `peer_id` | WG device RX bytes |
| `svc_peer_agent_register_total` | counter | `result` | Hub register outcomes (`ok` / `error`) |
| `svc_peer_agent_reconnect_total` | counter | `result` | Control WS connect outcomes (`ok` / `error`) |

`tx_bytes` / `rx_bytes` are read from the local WireGuard device:

| Backend | Source |
|---------|--------|
| kernel | `wgctrl` peer `TransmitBytes` / `ReceiveBytes` |
| userspace | wireguard-go IPC `tx_bytes` / `rx_bytes` |

Field `tx_rx_source` is always `"wireguard_device"` when counters are present. The hub is not used for TX/RX.

### Center allowlist (join tokens)

Center-only. Edge callers receive `403`. Network management stays on the center agent — not the main business app.

Durable state: `{state_dir}/allowlist.json` (alongside `agent_id`). Optional YAML `edge_tokens` are seeded into that file on center start (missing ids inserted; active ids updated; revoked ids are not resurrected).

On center connect and after local create/revoke, the agent syncs to the hub: `PUT /hub/allowlist` for active tokens and `DELETE /hub/tokens/{id}` for revoked ids.

### `GET /local/health`

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"ok"` |
| `role` | string | `center` or `edge` |
| `agent_id` | string | Local agent id |
| `hub_id` | string | Hub tenant (after register) |

### `GET /local/status`

| Field | Type | Description |
|-------|------|-------------|
| `role` | string | `center` or `edge` |
| `agent_id` | string | Local agent id |
| `hub_id` | string | Hub tenant |
| `name` | string | Configured name |
| `overlay_ip` | string | Assigned overlay IP |
| `center_agent_id` | string | Sole center id |
| `hub_connected` | bool | Control WebSocket connected |
| `center_connected` | bool | Edge: recent WG handshake with center; center: always true |
| `center_connectivity` | string | `online` / `offline` / `n/a` (center) |
| `wg_backend` | string | `kernel` or `userspace` |

### `GET /local/peers`

| Field | Type | Description |
|-------|------|-------------|
| `role` | string | Local role |
| `hub_id` | string | Hub tenant |
| `peers` | PeerView[] | See below |

**Center:** peers are edges from the hub registry (`GET /api/v1/agents`), excluding self/center, enriched with netmap + device stats when available.

**Edge:** peers come from the applied netmap (typically the center), with device stats.

**PeerView**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Peer agent id |
| `name` | string | From hub registry when available |
| `role` | string | `center` or `edge` |
| `overlay_ip` | string | Overlay address |
| `dns_name` | string | MagicDNS name |
| `online` | bool | Hub presence (center list) or derived from handshake |
| `last_seen` | string | Hub last seen (when from registry) |
| `endpoint` | string | Active UDP endpoint |
| `endpoint_summary` | string | `host:port` summary |
| `path` | string | `direct` or `relay` |
| `public_key` | string | Peer WG public key |
| `last_handshake` | string | RFC3339; omitted if none |
| `tx_bytes` | uint64 | Bytes transmitted to peer (WG device) |
| `rx_bytes` | uint64 | Bytes received from peer (WG device) |
| `tx_rx_source` | string | `"wireguard_device"` |

### `GET /local/peers/{id}`

Same body as one `PeerView`. `404` if the peer is not in the local view.

### `GET /local/allowlist`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "entries": AllowlistEntryView[] }` |

Secrets are redacted (`token` omitted). Each entry includes `id`, `label`, `tags`, `status` (`active` \| `revoked`), `created_at`, and optional `revoked_at`.

### `POST /local/allowlist`

| | |
|--|--|
| Role | `center` only |
| Request | `{ "id"?: string, "token"?: string, "label"?: string, "tags"?: string[] }` |
| Response | `201` AllowlistEntryView including `token` secret |

Empty `id` / `token` are generated. Persists to `{state_dir}/allowlist.json`, then best-effort hub sync.

### `DELETE /local/allowlist/{id}`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "status":"revoked", "id":"..." }` |

Marks the entry revoked on disk, then best-effort hub revoke/sync.

### `POST /local/allowlist/sync`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "hub_id", "upserted", "ids", "revoked" }` |

Forces a full push of active tokens and local revokes to the hub allowlist cache.

### `GET /local/grants`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "grants": GrantView[] }` |

Lists durable center-authored A2A grants (`active` and `revoked`). Each entry: `id`, `agent_a_id`, `agent_b_id`, `status`, `created_at`, optional `revoked_at`.

### `POST /local/grants`

| | |
|--|--|
| Role | `center` only |
| Request | `{ "id"?: string, "agent_a_id": string, "agent_b_id": string }` |
| Response | `201` GrantView |

Grants direct WireGuard peer connectivity between two registered agent IDs on the same hub (beyond default edge↔center). Empty `id` is generated. Persists to `{state_dir}/grants.json`, then best-effort hub sync (`POST /hub/grants` with the same id). Hub rebuilds netmap so both agents receive the peer; punch/relay tickets are issued only for allowed pairs.

### `DELETE /local/grants/{id}`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "status":"revoked", "id":"..." }` |

Marks the grant revoked on disk, then best-effort hub revoke/sync.

### `POST /local/grants/sync`

| | |
|--|--|
| Role | `center` only |
| Response | `200` `{ "hub_id", "upserted", "ids", "revoked" }` |

Forces a full push of active grants and local revokes to the hub (center `center_bootstrap` bearer).

---

## Relay: health and metrics

Served by `cmd/relay` on `http_listen_addr` (default `:3479`).

### `GET /health`

JSON `{"status":"ok","role":"relay"}`.

### `GET /metrics`

Prometheus text on `http_listen_addr` (same port as `/health` and `/relay`).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `svc_peer_relay_http_requests_total` | counter | `method`, `path`, `status` | HTTP requests |
| `svc_peer_relay_http_request_duration_seconds` | histogram | `method`, `path` | Request latency |
| `svc_peer_relay_sessions` | gauge | `transport` | Announced/connected peers (`udp`, `ws`, `all`) |
| `svc_peer_relay_forwards_total` | counter | `transport` | Frames forwarded (`udp` / `ws`) |
| `svc_peer_relay_bytes_total` | counter | `transport` | Payload bytes forwarded |

---

## Logging

All three binaries share config keys:

| Key | Values | Default |
|-----|--------|---------|
| `log_level` | `info`, `debug` | `info` |
| `log_format` | `text`, `json` | `text` |

Structured `log/slog` fields used where relevant: `component`, `hub_id`, `agent_id`, `peer_id`, `role`, `request_id`. HTTP access lines are Debug (Warn on 5xx).

---

## Related code

| Area | Path |
|------|------|
| Hub routes | `internal/hub/server.go`, `internal/hub/api.go` |
| Protocol types | `internal/protocol/types.go`, `internal/protocol/messages.go` |
| Agent local API | `internal/agent/localapi/` |
| Center allowlist store | `internal/agent/allowlist/` |
| Center grant store | `internal/agent/grants/` |
| WG device stats | `internal/agent/wgdev/` (`PeerStats`) |
| Logging | `internal/logging/` |
| Metrics | `internal/metrics/` |
