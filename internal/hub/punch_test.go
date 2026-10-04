package hub

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/betuah/svc-peer/internal/ticket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestIssueRelayTicketClaims(t *testing.T) {
	tok, exp, err := ticket.Issue("change-me-hub-secret", "agent-1", "agent-2", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("exp")
	}
	claims, err := ticket.Verify("change-me-hub-secret", tok, "agent-2", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Allows("agent-1") || !claims.Allows("agent-2") {
		t.Fatal("allows")
	}
}

func TestCoordinatePunchRequiresEndpoints(t *testing.T) {
	h, err := New(Config{
		HubSecret:           "s",
		OverlayCIDR:         "10.10.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := h.reg.RegisterFirstOrReconnect("t1", "", protocol.RegisterRequest{
		Name: "a", PublicKey: k1.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := h.reg.RegisterFirstOrReconnect("t2", "", protocol.RegisterRequest{
		Name: "b", PublicKey: k2.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = h.reg.UpdateEndpoints(a.ID, []protocol.Endpoint{{IP: "1.1.1.1", Port: 51820, Proto: "udp", Src: "host"}})
	_ = h.reg.UpdateEndpoints(b.ID, []protocol.Endpoint{{IP: "2.2.2.2", Port: 51820, Proto: "udp", Src: "srflx"}})
	h.coordinatePunch(a.ID)
}
