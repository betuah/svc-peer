// Unit tests: agent-local MagicDNS resolver.

package dns

import "testing"

func TestResolverLookup(t *testing.T) {
	r := NewResolver()
	r.Update(map[string]string{
		"cam-01.peer.local": "10.10.0.15",
		"cam-01":            "10.10.0.15",
	})
	ip, ok := r.Lookup("Cam-01.Peer.Local")
	if !ok || ip != "10.10.0.15" {
		t.Fatalf("lookup failed: ok=%v ip=%q", ok, ip)
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Fatal("expected miss")
	}
}
