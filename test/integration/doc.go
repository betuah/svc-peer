// Package integration holds end-to-end smoke tests that exercise multiple
// components together (hub HTTP, tokens, register). They are excluded from
// default `go test ./...` via the integration build tag.
//
//	go test -tags=integration ./test/integration/...
package integration
