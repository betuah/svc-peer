# svc-peer

svc-peer is a WireGuard overlay control and data-plane stack written in Go. Per `hub_id` there is exactly one **center** agent and many **edge** agents. Application traffic prefers direct WireGuard between edge and center. The hub assists with NAT (STUN, relay, thin signaling) and is not the preferred path for application data.

The center agent (`role=center`) is the network authority for join tokens, allowlist sync, ACL, and membership. The main business application is a separate process that only consumes overlay IPs / MagicDNS.

## Documentation

| Doc | Purpose |
|-----|---------|
| [docs/architecture.md](docs/architecture.md) | Architecture: binaries, center/edge, hub cloud vs self-host, ACL, NAT/relay, identity |
| [docs/deploy.md](docs/deploy.md) | Deploy: vendor cloud, self-host, TLS, Compose, GHCR release images, `CAP_NET_ADMIN` |
| [docs/api.md](docs/api.md) | Hub control APIs and agent local HTTP (including center `/local/allowlist`) |
| [docs/README.md](docs/README.md) | Docs index |

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

## Quick start

Requires Go 1.23.1 (see `go.mod`). Example configs live under `configs/`.

```bash
go build -o bin/hub ./cmd/hub
go build -o bin/agent ./cmd/agent
go build -o bin/relay ./cmd/relay

# WireGuard / TUN needs CAP_NET_ADMIN (or root):
sudo setcap cap_net_admin,cap_net_raw+ep ./bin/agent

go run ./cmd/hub -config configs/hub.example.yaml
go run ./cmd/relay -config configs/relay.example.yaml
sudo go run ./cmd/agent -config configs/agent-center.example.yaml
sudo go run ./cmd/agent -config configs/agent.example.yaml
```

Center local allowlist (join tokens; durable under `{state_dir}/allowlist.json`):

```bash
curl -s http://127.0.0.1:9100/local/allowlist
curl -s -X POST http://127.0.0.1:9100/local/allowlist \
  -H 'Content-Type: application/json' \
  -d '{"label":"cam-01","tags":["warehouse"]}'
curl -s -X POST http://127.0.0.1:9100/local/allowlist/sync
```

```bash
# Compose: hub + relay; add --profile agents for center/edge (needs /dev/net/tun)
docker compose up -d --build
docker compose --profile agents up -d --build
```

Replace example secrets before shared or production use. Deploy modes, hub TLS, placement, and capability notes: [docs/deploy.md](docs/deploy.md).

## Make targets

| Target | Action |
|--------|--------|
| `make build` | Build `bin/hub`, `bin/agent`, `bin/relay` |
| `make test` | Unit tests (`go test ./...`) |
| `make test-integration` | Integration suite (`-tags=integration`) |
| `make docker-build` | Build the three local images |
| `make compose-up` / `make compose-down` | Hub + relay Compose stack |
| `make certs` | Self-signed PEMs in `./certs` for local hub TLS |
| `make smoke-hub` | `GET /health` on the hub (`HUB_URL` optional) |

```bash
make build
make test
make certs                 # writes certs/cert.pem and certs/key.pem (gitignored)
make compose-up
make smoke-hub             # plain HTTP by default
# HUB_URL=https://127.0.0.1:8080 make smoke-hub   # after enabling hub TLS
```

Agent local APIs (`:9100` / `:9101`) require `docker compose --profile agents up -d` (needs `/dev/net/tun`). Mount `./certs` and set `tls_cert_file` / `tls_key_file` as in [docs/deploy.md](docs/deploy.md).

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
docs/                        architecture, deploy, API
scripts/                     gen-dev-certs, smoke-hub
Makefile                     common build/test/compose/cert targets
Dockerfile.hub|agent|relay   per-binary images
docker-compose.yml           hub, relay, optional agents profile
.github/workflows/ci.yml     vet, build, unit + integration tests
.github/workflows/release-images.yml  GHCR push on v* tags
test/integration/            integration tests (build tag integration)
```

## Tests

```bash
make test
make test-integration
# or: go test ./... && go test -tags=integration ./test/integration/...
```

CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `go vet`, `go build ./...`, `go test ./...`, and integration tests on PRs and `main`. Tag pushes matching `v*` run [`.github/workflows/release-images.yml`](.github/workflows/release-images.yml) to build and push `ghcr.io/betuah/svc-peer-{hub,agent,relay}` (see [docs/deploy.md](docs/deploy.md)).

## License

TBD
