# Tests

## Layout

| Kind | Location | How to run |
|------|----------|------------|
| **Unit** | Colocated `*_test.go` next to the package under test | `go test ./...` |
| **Integration / smoke** | `test/integration/` (build tag `integration`) | `go test -tags=integration ./test/integration/...` |

### Unit tests (package-aligned)

```
internal/hub/register_test.go      # local agent_id, one center, collisions, heartbeat
internal/hub/acl_test.go           # A2A grant store
internal/hub/netmap_acl_test.go    # edge↔center peers only; hub not dataplane
internal/hub/auth_roles_test.go    # center_bootstrap, allowlist sync, hub isolation
internal/hub/persist_test.go       # JSON state reload; offline after restart
internal/hub/punch_test.go         # punch only for allowed pairs
internal/agent/identity/           # local agent_id persist
internal/agent/config_test.go
internal/agent/localapi/           # loopback /local/* handlers
internal/ticket/ticket_test.go
internal/relay/frame_test.go
internal/agent/dns/magic_test.go
internal/agent/wgdev/*
```

### Integration tests

```
test/integration/hub_api_test.go     # local id persist, center+allowlist, edge↔center netmap
test/integration/hub_persist_test.go # hub restart membership + center allowlist re-sync
test/integration/local_api_test.go   # agent local HTTP peers/status with hub registry
```

## Commands

```bash
go test ./...
go test -tags=integration ./test/integration/...
```
