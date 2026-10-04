//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/agent/localapi"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

type integLocalView struct {
	role, agentID, hubID, name, overlay, centerID, backend string
	hubConn                                                bool
	peers                                                  []protocol.PeerConfig
	paths                                                  map[string]string
	hubURL                                                 string
	token                                                  string
	stats                                                  map[string]wgdev.PeerStats
}

func (v *integLocalView) Role() string          { return v.role }
func (v *integLocalView) AgentID() string       { return v.agentID }
func (v *integLocalView) HubID() string         { return v.hubID }
func (v *integLocalView) Name() string          { return v.name }
func (v *integLocalView) OverlayIP() string     { return v.overlay }
func (v *integLocalView) CenterAgentID() string { return v.centerID }
func (v *integLocalView) HubConnected() bool    { return v.hubConn }
func (v *integLocalView) WGBackend() string     { return v.backend }
func (v *integLocalView) NetmapPeers() ([]protocol.PeerConfig, map[string]string) {
	return v.peers, v.paths
}
func (v *integLocalView) ListHubAgents(ctx context.Context) (*protocol.AgentsListResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.hubURL+"/api/v1/agents", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+v.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		tErr := &httpError{status: res.Status, body: string(body)}
		return nil, tErr
	}
	var out protocol.AgentsListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (v *integLocalView) PeerDeviceStats(publicKey string) (wgdev.PeerStats, bool, error) {
	st, ok := v.stats[publicKey]
	return st, ok, nil
}

type httpError struct{ status, body string }

func (e *httpError) Error() string { return e.status + ": " + e.body }

func TestLocalAPICenterPeersFromHubAndWGStats(t *testing.T) {
	h := newTestHub(t, "hub-local-api")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	boot := "integration-boot-hub-local-api"
	centerID := uuid.NewString()
	center := register(t, srv.URL, boot, centerID, "center", protocol.RoleCenter)

	edgeTok := "spt_integ_edge_local_api"
	syncAllowlist(t, srv.URL, boot, []protocol.AllowlistToken{{
		ID: "seed-edge", Token: edgeTok, Label: "edge",
	}})
	edgeID := uuid.NewString()
	edge := register(t, srv.URL, edgeTok, edgeID, "cam", protocol.RoleEdge)

	hs := time.Now().UTC().Add(-15 * time.Second)
	view := &integLocalView{
		role:     protocol.RoleCenter,
		agentID:  center.AgentID,
		hubID:    center.HubID,
		name:     "center",
		overlay:  center.OverlayIP,
		centerID: center.AgentID,
		hubConn:  true,
		backend:  "userspace",
		hubURL:   srv.URL,
		token:    boot,
		peers: []protocol.PeerConfig{{
			PeerID: edge.AgentID, AgentID: edge.AgentID, Role: protocol.RoleEdge,
			PublicKey: "pk-edge-integ", AllowedIPs: []string{edge.OverlayIP + "/32"},
			Endpoint: "203.0.113.50:51820", DNSName: edge.DNSName,
		}},
		paths: map[string]string{edge.AgentID: protocol.PathDirect},
		stats: map[string]wgdev.PeerStats{
			"pk-edge-integ": {
				PublicKey: "pk-edge-integ", Endpoint: "203.0.113.50:51820",
				LastHandshake: hs, ReceiveBytes: 100, TransmitBytes: 200,
			},
		},
	}

	local := httptest.NewServer(localapi.New(view, nil, nil, nil).Handler())
	defer local.Close()

	res, err := http.Get(local.URL + "/local/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health: %s", res.Status)
	}

	res, err = http.Get(local.URL + "/local/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("peers: %s %s", res.Status, b)
	}
	var peers localapi.PeersResponse
	if err := json.NewDecoder(res.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers.Peers) != 1 || peers.Peers[0].ID != edge.AgentID {
		t.Fatalf("peers=%+v", peers.Peers)
	}
	p := peers.Peers[0]
	if p.TXBytes != 200 || p.RXBytes != 100 || p.TXRXSource != "wireguard_device" {
		t.Fatalf("tx/rx=%+v", p)
	}
	if p.Online == nil || !*p.Online {
		t.Fatal("expected edge online from hub registry")
	}
	wantIP, _, _ := strings.Cut(edge.OverlayIP, "/")
	if p.OverlayIP != wantIP {
		t.Fatalf("overlay_ip=%q want %q", p.OverlayIP, wantIP)
	}

	res, err = http.Get(local.URL + "/local/peers/" + edge.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var detail localapi.PeerView
	if err := json.NewDecoder(res.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.LastHandshake == nil {
		t.Fatal("expected last_handshake on detail")
	}
}

func TestLocalAPIEdgeStatus(t *testing.T) {
	hs := time.Now().UTC().Add(-10 * time.Second)
	view := &integLocalView{
		role:     protocol.RoleEdge,
		agentID:  "edge-a",
		hubID:    "hub-local-api",
		name:     "cam",
		overlay:  "10.88.0.9",
		centerID: "center-a",
		hubConn:  true,
		backend:  "kernel",
		peers: []protocol.PeerConfig{{
			PeerID: "center-a", AgentID: "center-a", Role: protocol.RoleCenter,
			PublicKey: "pk-c", AllowedIPs: []string{"10.88.0.1/32"},
		}},
		paths: map[string]string{"center-a": protocol.PathDirect},
		stats: map[string]wgdev.PeerStats{
			"pk-c": {PublicKey: "pk-c", LastHandshake: hs, TransmitBytes: 3, ReceiveBytes: 4},
		},
	}
	local := httptest.NewServer(localapi.New(view, nil, nil, nil).Handler())
	defer local.Close()

	res, err := http.Get(local.URL + "/local/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var st localapi.StatusResponse
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Role != protocol.RoleEdge || st.OverlayIP != "10.88.0.9" || !st.CenterConnected {
		t.Fatalf("status=%+v", st)
	}
}

func syncAllowlist(t *testing.T, srvURL, bearer string, tokens []protocol.AllowlistToken) {
	t.Helper()
	body, err := json.Marshal(protocol.AllowlistSyncRequest{Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, srvURL+"/hub/allowlist", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("allowlist: %s %s", res.Status, b)
	}
}
