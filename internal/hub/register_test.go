// Unit tests: local agent_id register, center claim, reconnect, heartbeat.

package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestRegisterPresentedLocalAgentID(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", 45*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	a1, created, err := reg.RegisterPresented("550e8400-e29b-41d4-a716-446655440000", "", protocol.RoleCenter, protocol.RegisterRequest{
		AgentID: "550e8400-e29b-41d4-a716-446655440000",
		Name:    "center-app", PublicKey: "pubkey-C",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || a1.Role != protocol.RoleCenter {
		t.Fatalf("center first register: created=%v role=%s", created, a1.Role)
	}
	if reg.CenterAgentID() != a1.ID {
		t.Fatal("center id not set")
	}

	a2, created2, err := reg.RegisterPresented(a1.ID, "", protocol.RoleCenter, protocol.RegisterRequest{
		AgentID: a1.ID, Name: "center-app", PublicKey: "pubkey-C",
	})
	if err != nil || created2 || a2.ID != a1.ID || a2.OverlayIP != a1.OverlayIP {
		t.Fatalf("reconnect: created=%v err=%v a2=%+v", created2, err, a2)
	}
}

func TestOneCenterPerHub(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterPresented("center-1", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "c1", PublicKey: "pk1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterPresented("center-2", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "c2", PublicKey: "pk2",
	})
	if err != ErrCenterExists {
		t.Fatalf("want ErrCenterExists, got %v", err)
	}
}

func TestAgentIDCollisionRejected(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.10.0.0/16", "peer.local", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterPresented("same-id", "tok-a", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "e1", PublicKey: "pk1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = reg.RegisterPresented("same-id", "tok-b", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "e2", PublicKey: "pk2",
	})
	if err != ErrAgentIDCollision {
		t.Fatalf("want collision, got %v", err)
	}
}

func TestHeartbeatOnlineOffline(t *testing.T) {
	reg, err := NewRegistry("hub-main", "10.20.0.0/24", "peer.local", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := reg.RegisterPresented("viewer-id", "t1", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "viewer-01", PublicKey: "pubkey-B",
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	flipped := reg.SweepOffline()
	if len(flipped) != 1 || flipped[0] != a.ID {
		t.Fatalf("expected offline, got %v", flipped)
	}
	if err := reg.Heartbeat(a.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := reg.Get(a.ID)
	if !got.Online {
		t.Fatal("expected online after heartbeat")
	}
}
