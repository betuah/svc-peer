package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testHubPeer(t *testing.T) HubPeer {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return HubPeer{
		PeerID:    PeerIDHub,
		PublicKey: k.PublicKey().String(),
		Endpoint:  "203.0.113.1:51820",
		OverlayIP: "10.10.0.1/32",
		DNSName:   "hub.peer.local",
	}
}

func TestNetmapDefaultAgentPeersHubOnly(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a1, _, err := reg.RegisterFirstOrReconnect("t1", "", protocol.RegisterRequest{
		Name: "cam-01", PublicKey: "pk1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterFirstOrReconnect("t2", "", protocol.RegisterRequest{
		Name: "viewer-01", PublicKey: "pk2",
	})
	if err != nil {
		t.Fatal(err)
	}

	grants := NewGrantStore()
	nm := NewNetmapBuilder(reg, grants, testHubPeer(t)).ForAgent(a1.ID)
	if len(nm.Peers) != 1 {
		t.Fatalf("default ACL: expected hub-only peer list, got %d peers: %+v", len(nm.Peers), nm.Peers)
	}
	if nm.Peers[0].PeerID != PeerIDHub {
		t.Fatalf("expected hub peer, got %+v", nm.Peers[0])
	}
	// MagicDNS may still list other agents (resolution ≠ dataplane permission).
	if nm.DNSMap["viewer-01.peer.local"] == "" {
		t.Fatalf("dns map should include hub agents: %#v", nm.DNSMap)
	}
	// No hairpin: hub AllowedIPs must not advertise the full overlay / other agents.
	for _, ip := range nm.Peers[0].AllowedIPs {
		if ip == "10.10.0.0/16" {
			t.Fatal("hub AllowedIPs must not include full overlay (no hairpin)")
		}
	}
}

func TestNetmapGrantAddsDirectA2APeers(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
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

	grants := NewGrantStore()
	if _, err := grants.Grant(a1.ID, a2.ID); err != nil {
		t.Fatal(err)
	}
	nm := NewNetmapBuilder(reg, grants, testHubPeer(t)).ForAgent(a1.ID)
	if len(nm.Peers) != 2 {
		t.Fatalf("expected hub + granted peer, got %d", len(nm.Peers))
	}
	var sawHub, sawA2 bool
	for _, p := range nm.Peers {
		switch p.PeerID {
		case PeerIDHub:
			sawHub = true
		case a2.ID:
			sawA2 = true
			if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != a2.OverlayIP.String() {
				t.Fatalf("granted peer AllowedIPs: %v", p.AllowedIPs)
			}
		default:
			t.Fatalf("unexpected peer %q", p.PeerID)
		}
	}
	if !sawHub || !sawA2 {
		t.Fatalf("missing peers hub=%v a2=%v", sawHub, sawA2)
	}
}

func TestNetmapHubPeersAllAgents(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
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
	nm := NewNetmapBuilder(reg, NewGrantStore(), testHubPeer(t)).ForHub()
	if len(nm.Peers) != 2 {
		t.Fatalf("hub netmap should list all agents, got %d", len(nm.Peers))
	}
	ids := map[string]bool{}
	for _, p := range nm.Peers {
		ids[p.PeerID] = true
	}
	if !ids[a1.ID] || !ids[a2.ID] {
		t.Fatalf("hub peers missing agents: %+v", nm.Peers)
	}
}
