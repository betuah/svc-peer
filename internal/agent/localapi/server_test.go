package localapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
)

type fakeView struct {
	role, agentID, hubID, name, overlay, centerID, backend string
	hubConn                                                bool
	peers                                                  []protocol.PeerConfig
	paths                                                  map[string]string
	agents                                                 *protocol.AgentsListResponse
	agentsErr                                              error
	stats                                                  map[string]wgdev.PeerStats
}

func (f *fakeView) Role() string            { return f.role }
func (f *fakeView) AgentID() string         { return f.agentID }
func (f *fakeView) HubID() string           { return f.hubID }
func (f *fakeView) Name() string            { return f.name }
func (f *fakeView) OverlayIP() string       { return f.overlay }
func (f *fakeView) CenterAgentID() string   { return f.centerID }
func (f *fakeView) HubConnected() bool      { return f.hubConn }
func (f *fakeView) WGBackend() string       { return f.backend }
func (f *fakeView) NetmapPeers() ([]protocol.PeerConfig, map[string]string) {
	return f.peers, f.paths
}
func (f *fakeView) ListHubAgents(context.Context) (*protocol.AgentsListResponse, error) {
	return f.agents, f.agentsErr
}
func (f *fakeView) PeerDeviceStats(publicKey string) (wgdev.PeerStats, bool, error) {
	st, ok := f.stats[publicKey]
	return st, ok, nil
}

func TestCenterLocalPeersIncludesTXRX(t *testing.T) {
	hs := time.Unix(1700000000, 0).UTC()
	v := &fakeView{
		role:     protocol.RoleCenter,
		agentID:  "center-1",
		hubID:    "hub-main",
		name:     "center",
		overlay:  "10.88.0.1",
		centerID: "center-1",
		backend:  "userspace",
		hubConn:  true,
		peers: []protocol.PeerConfig{{
			PeerID: "edge-1", AgentID: "edge-1", Role: protocol.RoleEdge,
			PublicKey: "pk-edge", AllowedIPs: []string{"10.88.0.2/32"},
			Endpoint: "203.0.113.5:51820", DNSName: "edge-1.peer.local",
		}},
		paths: map[string]string{"edge-1": protocol.PathDirect},
		agents: &protocol.AgentsListResponse{
			HubID: "hub-main", CenterAgentID: "center-1",
			Agents: []protocol.AgentSummary{
				{ID: "center-1", Name: "center", Role: protocol.RoleCenter, OverlayIP: "10.88.0.1", Online: true},
				{ID: "edge-1", Name: "cam", Role: protocol.RoleEdge, OverlayIP: "10.88.0.2", Online: true, LastSeen: hs},
			},
		},
		stats: map[string]wgdev.PeerStats{
			"pk-edge": {PublicKey: "pk-edge", Endpoint: "203.0.113.5:51820", LastHandshake: hs, ReceiveBytes: 10, TransmitBytes: 20},
		},
	}
	s := New(v, nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/local/peers", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	var out PeersResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Peers) != 1 {
		t.Fatalf("peers=%d", len(out.Peers))
	}
	p := out.Peers[0]
	if p.ID != "edge-1" || p.TXBytes != 20 || p.RXBytes != 10 {
		t.Fatalf("peer=%+v", p)
	}
	if p.TXRXSource != "wireguard_device" {
		t.Fatalf("source=%q", p.TXRXSource)
	}
	if p.LastHandshake == nil || !p.LastHandshake.Equal(hs) {
		t.Fatalf("handshake=%v", p.LastHandshake)
	}
	if p.Online == nil || !*p.Online {
		t.Fatal("expected online")
	}
}

func TestEdgeLocalStatusAndPeers(t *testing.T) {
	hs := time.Now().UTC().Add(-30 * time.Second)
	v := &fakeView{
		role:     protocol.RoleEdge,
		agentID:  "edge-1",
		hubID:    "hub-main",
		name:     "cam",
		overlay:  "10.88.0.2",
		centerID: "center-1",
		hubConn:  true,
		backend:  "kernel",
		peers: []protocol.PeerConfig{{
			PeerID: "center-1", AgentID: "center-1", Role: protocol.RoleCenter,
			PublicKey: "pk-center", AllowedIPs: []string{"10.88.0.1/32"},
			Endpoint: "198.51.100.1:51820",
		}},
		paths: map[string]string{"center-1": protocol.PathDirect},
		stats: map[string]wgdev.PeerStats{
			"pk-center": {PublicKey: "pk-center", LastHandshake: hs, ReceiveBytes: 5, TransmitBytes: 7, Endpoint: "198.51.100.1:51820"},
		},
	}
	s := New(v, nil)

	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/local/status", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("status code=%d", res.Code)
	}
	var st StatusResponse
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.CenterConnected || st.CenterConnectivity != "online" || st.OverlayIP != "10.88.0.2" {
		t.Fatalf("status=%+v", st)
	}

	res = httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/local/peers", nil))
	var peers PeersResponse
	if err := json.NewDecoder(res.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers.Peers) != 1 || peers.Peers[0].ID != "center-1" {
		t.Fatalf("peers=%+v", peers.Peers)
	}
	if peers.Peers[0].TXBytes != 7 || peers.Peers[0].RXBytes != 5 {
		t.Fatalf("tx/rx=%+v", peers.Peers[0])
	}

	res = httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/local/peers/center-1", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("detail=%d", res.Code)
	}
	var detail PeerView
	if err := json.NewDecoder(res.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.LastHandshake == nil {
		t.Fatal("expected last_handshake on detail")
	}
}

func TestLocalHealth(t *testing.T) {
	s := New(&fakeView{role: protocol.RoleCenter, agentID: "c1", hubID: "h1"}, nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/local/health", nil))
	if res.Code != http.StatusOK {
		t.Fatal(res.Code)
	}
	var h HealthResponse
	_ = json.NewDecoder(res.Body).Decode(&h)
	if h.Status != "ok" || h.Role != protocol.RoleCenter {
		t.Fatalf("%+v", h)
	}
}
