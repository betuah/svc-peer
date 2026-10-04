package pathmgr

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
)

type stubDevice struct {
	endpoint string
}

func (d *stubDevice) Backend() string { return "stub" }
func (d *stubDevice) Up(wgdev.InterfaceConfig) error {
	return nil
}
func (d *stubDevice) ConfigurePeers(uint64, []protocol.PeerConfig) error { return nil }
func (d *stubDevice) UpdatePeerEndpoint(_, endpoint string) error {
	d.endpoint = endpoint
	return nil
}
func (d *stubDevice) PeerLastHandshake(string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (d *stubDevice) PeerStats(string) (wgdev.PeerStats, bool, error) {
	return wgdev.PeerStats{}, false, nil
}
func (d *stubDevice) Close() error { return nil }

type stubCtrl struct{}

func (stubCtrl) Send(protocol.Envelope) error { return nil }

func TestHandlePunchPrefersPrivateHost(t *testing.T) {
	dev := &stubDevice{}
	m := New(dev, nil, stubCtrl{}, slog.Default())
	m.mu.Lock()
	m.peers["peer-a"] = protocol.PeerConfig{PeerID: "peer-a", PublicKey: "pk"}
	m.mu.Unlock()

	m.HandlePunch(context.Background(), "peer-a", []protocol.Endpoint{
		{IP: "203.0.113.8", Port: 51820, Src: protocol.EndpointSrcSrflx},
		{IP: "198.51.100.2", Port: 51820, Src: protocol.EndpointSrcHost},
		{IP: "192.168.10.4", Port: 51820, Src: protocol.EndpointSrcHost},
	})
	if dev.endpoint != "192.168.10.4:51820" {
		t.Fatalf("endpoint=%q want private host", dev.endpoint)
	}
}
