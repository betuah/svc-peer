package hub

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestPersistReloadAgentsAndAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub-state.json")

	h1, err := New(Config{
		ListenAddr:          ":0",
		HubID:               "hub-persist",
		CenterBootstrap:     "boot-persist",
		ManagementTokenSeed: "mgmt-persist",
		RelaySecret:         "relay-persist",
		OverlayCIDR:         "10.55.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		StatePath:           path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	center, _, err := h1.Registry().RegisterPresented("center-1", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "center", PublicKey: "pk-center",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !center.Online {
		t.Fatal("fresh register should be online")
	}

	_, err = h1.Tokens().UpsertEdgeAllowlist([]protocol.AllowlistToken{
		{ID: "edge-tok", Token: "spt_persist_edge", Label: "cam", Tags: []string{"site-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h1.Tokens().BindAgentID("edge-tok", "edge-1"); err != nil {
		t.Fatal(err)
	}
	edge, _, err := h1.Registry().RegisterPresented("edge-1", "edge-tok", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "cam", PublicKey: "pk-edge",
	})
	if err != nil {
		t.Fatal(err)
	}
	h1.Registry().Heartbeat("edge-1")
	if err := h1.Persist(); err != nil {
		t.Fatal(err)
	}

	h2, err := New(Config{
		ListenAddr:          ":0",
		HubID:               "hub-persist",
		CenterBootstrap:     "boot-persist",
		ManagementTokenSeed: "mgmt-persist",
		RelaySecret:         "relay-persist",
		OverlayCIDR:         "10.55.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		StatePath:           path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if h2.Registry().CenterAgentID() != "center-1" {
		t.Fatalf("center id: %q", h2.Registry().CenterAgentID())
	}
	restoredCenter, err := h2.Registry().Get("center-1")
	if err != nil {
		t.Fatal(err)
	}
	if restoredCenter.Online {
		t.Fatal("restored agents must be offline until heartbeat/register")
	}
	if restoredCenter.PublicKey != "pk-center" || restoredCenter.OverlayIP != center.OverlayIP {
		t.Fatalf("center membership: %+v vs %+v", restoredCenter, center)
	}
	restoredEdge, err := h2.Registry().Get("edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if restoredEdge.Online || restoredEdge.OverlayIP != edge.OverlayIP || restoredEdge.PublicKey != "pk-edge" {
		t.Fatalf("edge membership: %+v", restoredEdge)
	}
	if h2.Registry().OnlineCount() != 0 {
		t.Fatalf("online count after restart: %d", h2.Registry().OnlineCount())
	}

	tok, err := h2.Tokens().Lookup("spt_persist_edge")
	if err != nil {
		t.Fatal(err)
	}
	if tok.ID != "edge-tok" || tok.AgentID != "edge-1" || tok.Label != "cam" {
		t.Fatalf("allowlist: %+v", tok)
	}

	// Overlay IP preserved on reconnect.
	again, created, err := h2.Registry().RegisterPresented("edge-1", "edge-tok", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "cam", PublicKey: "pk-edge",
	})
	if err != nil || created {
		t.Fatalf("reconnect: created=%v err=%v", created, err)
	}
	if again.OverlayIP != edge.OverlayIP || !again.Online {
		t.Fatalf("reconnect overlay/online: %+v", again)
	}
}

func TestPersistRejectsHubIDMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := NewFileStore(path)
	if err := store.Save(&stateFile{
		HubID: "hub-a",
		Agents: []persistedAgent{{
			ID: "c1", Role: protocol.RoleCenter, Name: "c", PublicKey: "pk",
			OverlayIP: "10.55.0.2/32",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		ListenAddr:      ":0",
		HubID:           "hub-b",
		CenterBootstrap: "boot",
		RelaySecret:     "relay",
		OverlayCIDR:     "10.55.0.0/16",
		StatePath:       path,
	}, nil)
	if err == nil {
		t.Fatal("expected hub_id mismatch error")
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	store := NewFileStore(path)
	st := &stateFile{
		HubID: "hub-x",
		Agents: []persistedAgent{{
			ID: "a1", Role: protocol.RoleEdge, Name: "e", PublicKey: "pk",
			OverlayIP: netip.MustParsePrefix("10.1.0.3/32").String(),
			TokenID:   "t1",
		}},
		EdgeTokens: []persistedToken{{
			ID: "t1", Role: RoleEdgeToken, Hash: "abc", CreatedAt: time.Unix(100, 0).UTC(),
		}},
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got == nil {
		t.Fatalf("load: %v %#v", err, got)
	}
	if got.HubID != "hub-x" || len(got.Agents) != 1 || len(got.EdgeTokens) != 1 {
		t.Fatalf("got: %+v", got)
	}
	if got.Agents[0].OverlayIP != "10.1.0.3/32" || got.EdgeTokens[0].Hash != "abc" {
		t.Fatalf("fields: %+v %+v", got.Agents[0], got.EdgeTokens[0])
	}
}
