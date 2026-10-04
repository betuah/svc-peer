# Tests

## Layout

| Kind | Location | How to run |
|------|----------|------------|
| **Unit** | Colocated `*_test.go` next to the package under test | `go test ./...` |
| **Integration / smoke** | `test/integration/` (build tag `integration`) | `go test -tags=integration ./test/integration/...` |

### Unit tests (package-aligned)

```
internal/hub/register_test.go      # token bind, reconnect, heartbeat, netmap
internal/hub/punch_test.go         # punch coordination + relay ticket claims
internal/ticket/ticket_test.go     # HMAC ticket issue/verify
internal/relay/frame_test.go       # relay frame codec
internal/agent/dns/magic_test.go   # MagicDNS resolver
internal/agent/wgdev/select_test.go # kernel-first backend selection
internal/agent/wgdev/keys_test.go  # keygen + peer config conversion
```

Default `go test ./...` runs **only unit tests**. Integration sources use `//go:build integration` so they are not part of the default set.

### Integration tests

```
test/integration/doc.go
test/integration/hub_api_test.go   # in-process hub: mint → register → reconnect
```

These need no CAP_NET_ADMIN (control plane only). Full two-agent WG dataplane smoke remains a manual/sudo procedure (see root README).

## Commands

```bash
# Unit (CI default)
go test ./...

# Integration
go test -tags=integration ./test/integration/...

# Both
go test ./... && go test -tags=integration ./test/integration/...
```
