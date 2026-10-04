package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestNetmapEdgePeersOnlyCenter(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	center, _, err := reg.RegisterPresented("center-id", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "center", PublicKey: "pk-c",
	})
	if err != nil {
		t.Fatal(err)
	}
	edge, _, err := reg.RegisterPresented("edge-id", "t1", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "cam-01", PublicKey: "pk-e",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterPresented("edge-2", "t2", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "cam-02", PublicKey: "pk-e2",
	})
	if err != nil {
		t.Fatal(err)
	}

	nm := NewNetmapBuilder(reg, NewGrantStore()).ForAgent(edge.ID)
	if len(nm.Peers) != 1 {
		t.Fatalf("edge should peer only center, got %d: %+v", len(nm.Peers), nm.Peers)
	}
	if nm.Peers[0].PeerID != center.ID || nm.Peers[0].Role != protocol.RoleCenter {
		t.Fatalf("peer: %+v", nm.Peers[0])
	}
	if nm.CenterAgentID != center.ID {
		t.Fatalf("center_agent_id: %s", nm.CenterAgentID)
	}
	for _, p := range nm.Peers {
		if p.PeerID == "hub" || p.Role == "hub" {
			t.Fatal("hub must not be app dataplane peer")
		}
	}
}

func TestNetmapCenterPeersAllEdges(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	center, _, err := reg.RegisterPresented("center-id", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "center", PublicKey: "pk-c",
	})
	if err != nil {
		t.Fatal(err)
	}
	e1, _, _ := reg.RegisterPresented("e1", "t1", protocol.RoleEdge, protocol.RegisterRequest{Name: "e1", PublicKey: "pk1"})
	e2, _, _ := reg.RegisterPresented("e2", "t2", protocol.RoleEdge, protocol.RegisterRequest{Name: "e2", PublicKey: "pk2"})

	nm := NewNetmapBuilder(reg, NewGrantStore()).ForAgent(center.ID)
	if len(nm.Peers) != 2 {
		t.Fatalf("center should peer all edges, got %d", len(nm.Peers))
	}
	ids := map[string]bool{}
	for _, p := range nm.Peers {
		ids[p.PeerID] = true
		if p.Role != protocol.RoleEdge {
			t.Fatalf("expected edge role: %+v", p)
		}
	}
	if !ids[e1.ID] || !ids[e2.ID] {
		t.Fatalf("missing edges: %+v", nm.Peers)
	}
}

func TestNetmapEdgeEdgeDeniedWithoutGrant(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = reg.RegisterPresented("c", "", protocol.RoleCenter, protocol.RegisterRequest{Name: "c", PublicKey: "pkc"})
	e1, _, _ := reg.RegisterPresented("e1", "t1", protocol.RoleEdge, protocol.RegisterRequest{Name: "e1", PublicKey: "pk1"})
	e2, _, _ := reg.RegisterPresented("e2", "t2", protocol.RoleEdge, protocol.RegisterRequest{Name: "e2", PublicKey: "pk2"})
	b := NewNetmapBuilder(reg, NewGrantStore())
	if b.AllowedPeer(e1.ID, e2.ID) {
		t.Fatal("edge↔edge must be denied by default")
	}
	if !b.AllowedPeer(e1.ID, "c") {
		t.Fatal("edge↔center must be allowed")
	}
}
