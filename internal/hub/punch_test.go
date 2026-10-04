package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/betuah/svc-peer/internal/ticket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestIssueRelayTicketClaims(t *testing.T) {
	tok, exp, err := ticket.Issue("change-me-relay-secret", "agent-1", "agent-2", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("exp")
	}
	claims, err := ticket.Verify("change-me-relay-secret", tok, "agent-2", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Allows("agent-1") || !claims.Allows("agent-2") {
		t.Fatal("allows")
	}
}

func TestCoordinatePunchOnlyAllowedPairs(t *testing.T) {
	h, err := New(Config{
		HubID:               "hub-main",
		CenterBootstrap:     "boot",
		ManagementTokenSeed: "mgmt",
		RelaySecret:         "relay",
		OverlayCIDR:         "10.10.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	k3, _ := wgtypes.GeneratePrivateKey()
	c, _, err := h.reg.RegisterPresented("c", "", protocol.RoleCenter, protocol.RegisterRequest{
		Name: "c", PublicKey: k1.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e1, _, err := h.reg.RegisterPresented("e1", "t1", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "e1", PublicKey: k2.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	e2, _, err := h.reg.RegisterPresented("e2", "t2", protocol.RoleEdge, protocol.RegisterRequest{
		Name: "e2", PublicKey: k3.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.reg.UpdateEndpoints(c.ID, []protocol.Endpoint{{IP: "1.1.1.1", Port: 51820, Proto: "udp", Src: "host"}})
	_ = h.reg.UpdateEndpoints(e1.ID, []protocol.Endpoint{{IP: "2.2.2.2", Port: 51820, Proto: "udp", Src: "host"}})
	_ = h.reg.UpdateEndpoints(e2.ID, []protocol.Endpoint{{IP: "3.3.3.3", Port: 51820, Proto: "udp", Src: "srflx"}})
	// Edge↔edge not allowed; edge↔center is — should not panic.
	h.coordinatePunch(e1.ID)
	if h.netmap.AllowedPeer(e1.ID, e2.ID) {
		t.Fatal("edge↔edge should be denied")
	}
	if !h.netmap.AllowedPeer(e1.ID, c.ID) {
		t.Fatal("edge↔center should be allowed")
	}
}
