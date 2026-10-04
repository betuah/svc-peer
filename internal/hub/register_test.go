// Unit tests: token bind on first register, reconnect identity, heartbeat, netmap DNS.

package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestTokenBindAgentIDOnFirstRegister(t *testing.T) {
	tokens := NewTokenStore()
	rec, raw, err := tokens.Mint("cam", []string{"warehouse"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.AgentID != "" {
		t.Fatalf("agent id must be empty at mint, got %q", rec.AgentID)
	}

	looked, err := tokens.Lookup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if looked.ID != rec.ID {
		t.Fatalf("lookup id mismatch")
	}

	reg, err := NewRegistry("10.10.0.0/16", "peer.local", 45*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	a1, created, err := reg.RegisterFirstOrReconnect(looked.ID, looked.AgentID, protocol.RegisterRequest{
		Name:      "cam-warehouse-01",
		PublicKey: "pubkey-A",
		Tags:      []string{"warehouse"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected first register to create agent")
	}
	if a1.ID == "" {
		t.Fatal("expected agent id")
	}
	if err := tokens.BindAgentID(looked.ID, a1.ID); err != nil {
		t.Fatal(err)
	}

	bound, err := tokens.Lookup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bound.AgentID != a1.ID {
		t.Fatalf("token not bound: got %q want %q", bound.AgentID, a1.ID)
	}

	// Reconnect with same token → same agent id / overlay IP.
	a2, created2, err := reg.RegisterFirstOrReconnect(bound.ID, bound.AgentID, protocol.RegisterRequest{
		Name:      "cam-warehouse-01",
		PublicKey: "pubkey-A",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Fatal("reconnect must not create a new agent")
	}
	if a2.ID != a1.ID {
		t.Fatalf("agent id changed on reconnect: %s → %s", a1.ID, a2.ID)
	}
	if a2.OverlayIP != a1.OverlayIP {
		t.Fatalf("overlay ip changed on reconnect")
	}
}

func TestHeartbeatOnlineOffline(t *testing.T) {
	reg, err := NewRegistry("10.20.0.0/24", "peer.local", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenStore()
	rec, _, err := tokens.Mint("", nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := reg.RegisterFirstOrReconnect(rec.ID, "", protocol.RegisterRequest{
		Name:      "viewer-01",
		PublicKey: "pubkey-B",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Online {
		t.Fatal("expected online after register")
	}

	// Force last seen into the past by sweeping after timeout.
	time.Sleep(40 * time.Millisecond)
	flipped := reg.SweepOffline()
	if len(flipped) != 1 || flipped[0] != a.ID {
		t.Fatalf("expected agent marked offline, got %v", flipped)
	}
	got, err := reg.Get(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Online {
		t.Fatal("expected offline")
	}

	if err := reg.Heartbeat(a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = reg.Get(a.ID)
	if !got.Online {
		t.Fatal("expected online after heartbeat")
	}
}

func TestNetmapIncludesAgentPeersAndDNSMap(t *testing.T) {
	reg, err := NewRegistry("10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a1, _, err := reg.RegisterFirstOrReconnect("t1", "", protocol.RegisterRequest{
		Name: "cam-01", PublicKey: "pk1",
	})
	if err != nil {
		t.Fatal(err)
	}
	a2, _, err := reg.RegisterFirstOrReconnect("t2", "", protocol.RegisterRequest{
		Name: "viewer-01", PublicKey: "pk2",
	})
	if err != nil {
		t.Fatal(err)
	}

	nm := NewNetmapBuilder(reg).ForAgent(a1.ID)
	if len(nm.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(nm.Peers))
	}
	if nm.Peers[0].AgentID != a2.ID {
		t.Fatalf("peer agent mismatch")
	}
	if nm.DNSMap["cam-01.peer.local"] == "" || nm.DNSMap["viewer-01.peer.local"] == "" {
		t.Fatalf("dns map incomplete: %#v", nm.DNSMap)
	}
}
