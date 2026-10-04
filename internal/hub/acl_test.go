package hub

import "testing"

func TestGrantStoreDefaultDeniesA2A(t *testing.T) {
	g := NewGrantStore()
	if g.Allowed("a", "b") {
		t.Fatal("default ACL must deny agent↔agent")
	}
	if peers := g.PeersOf("a"); len(peers) != 0 {
		t.Fatalf("expected no granted peers, got %v", peers)
	}
}

func TestGrantStoreAddsReciprocalPeers(t *testing.T) {
	g := NewGrantStore()
	grant, err := g.Grant("agent-a", "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if grant.ID == "" {
		t.Fatal("expected grant id")
	}
	if !g.Allowed("agent-a", "agent-b") || !g.Allowed("agent-b", "agent-a") {
		t.Fatal("grant must be reciprocal")
	}
	peers := g.PeersOf("agent-a")
	if len(peers) != 1 || peers[0] != "agent-b" {
		t.Fatalf("PeersOf a: %v", peers)
	}
	peers = g.PeersOf("agent-b")
	if len(peers) != 1 || peers[0] != "agent-a" {
		t.Fatalf("PeersOf b: %v", peers)
	}

	if err := g.Revoke(grant.ID); err != nil {
		t.Fatal(err)
	}
	if g.Allowed("agent-a", "agent-b") {
		t.Fatal("revoke must remove grant")
	}
}

func TestGrantStoreRejectsSelfAndDuplicate(t *testing.T) {
	g := NewGrantStore()
	if _, err := g.Grant("a", "a"); err == nil {
		t.Fatal("self grant must fail")
	}
	if _, err := g.Grant("a", "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Grant("b", "a"); err == nil {
		t.Fatal("duplicate pair must fail")
	}
}

func TestGrantStoreWithIDIdempotent(t *testing.T) {
	g := NewGrantStore()
	first, created, err := g.GrantWithID("g1", "e1", "e2")
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	again, created, err := g.GrantWithID("g1", "e1", "e2")
	if err != nil || created {
		t.Fatalf("idempotent: created=%v err=%v", created, err)
	}
	if again.ID != first.ID {
		t.Fatalf("id mismatch: %s vs %s", again.ID, first.ID)
	}
	if _, _, err := g.GrantWithID("g1", "e3", "e4"); err != ErrGrantExists {
		t.Fatalf("same id different pair: %v", err)
	}
	if _, _, err := g.GrantWithID("g2", "e2", "e1"); err != ErrGrantExists {
		t.Fatalf("same pair different id: %v", err)
	}
}
