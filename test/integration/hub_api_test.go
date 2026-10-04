//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/betuah/svc-peer/internal/agent/identity"
	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestHub(t *testing.T, hubID string) *hub.Hub {
	t.Helper()
	h, err := hub.New(hub.Config{
		ListenAddr:          ":0",
		HubID:               hubID,
		CenterBootstrap:     "integration-boot-" + hubID,
		ManagementTokenSeed: "integration-mgmt-" + hubID,
		RelaySecret:         "integration-relay-" + hubID,
		OverlayCIDR:         "10.88.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		STUNURLs:            []string{"stun:stun.l.google.com:19302"},
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func register(t *testing.T, srvURL, bearer, agentID, name, role string) protocol.RegisterResponse {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(protocol.RegisterRequest{
		AgentID: agentID, Name: name, PublicKey: key.PublicKey().String(), Role: role,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, srvURL+"/api/v1/agents/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+bearer)
	r.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("register: %s %s", res.Status, b)
	}
	var out protocol.RegisterResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLocalAgentIDPersistAndCenterEdgeJoin(t *testing.T) {
	dir := t.TempDir()
	id1, err := identity.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := identity.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("persist failed: %s vs %s", id1, id2)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "agent_id"))
	if err != nil || string(raw) != id1+"\n" {
		t.Fatalf("file: %q err=%v", raw, err)
	}

	h := newTestHub(t, "hub-it")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	centerID := uuid.NewString()
	center := register(t, srv.URL, "integration-boot-hub-it", centerID, "center", protocol.RoleCenter)
	if center.AgentID != centerID || center.Role != protocol.RoleCenter {
		t.Fatalf("center: %+v", center)
	}

	edgeTok := "spt_it_edge_01"
	syncBody, _ := json.Marshal(protocol.AllowlistSyncRequest{
		Tokens: []protocol.AllowlistToken{{ID: "seed-edge", Token: edgeTok, Label: "cam"}},
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer integration-boot-hub-it")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlist sync status %d", resp.StatusCode)
	}

	edgeID := id1 // use persisted local id
	edge := register(t, srv.URL, edgeTok, edgeID, "cam-it", protocol.RoleEdge)
	if edge.AgentID != edgeID {
		t.Fatalf("hub must not rewrite agent_id: %s vs %s", edge.AgentID, edgeID)
	}
	if len(edge.Peers) != 1 || edge.Peers[0].PeerID != centerID || edge.Peers[0].Role != protocol.RoleCenter {
		t.Fatalf("edge peers: %+v", edge.Peers)
	}

	// Reconnect same local id.
	again := register(t, srv.URL, edgeTok, edgeID, "cam-it", protocol.RoleEdge)
	if again.AgentID != edge.AgentID || again.OverlayIP != edge.OverlayIP {
		t.Fatalf("reconnect identity changed")
	}

	hres, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer hres.Body.Close()
	var health protocol.HealthResponse
	_ = json.NewDecoder(hres.Body).Decode(&health)
	if health.Status != "ok" || health.HubID != "hub-it" || health.CenterAgentID != centerID {
		t.Fatalf("health: %+v", health)
	}
}

func TestOneCenterAndEdgeNetmap(t *testing.T) {
	h := newTestHub(t, "hub-a")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	centerID := uuid.NewString()
	register(t, srv.URL, "integration-boot-hub-a", centerID, "center", protocol.RoleCenter)

	syncBody, _ := json.Marshal(protocol.AllowlistSyncRequest{
		Tokens: []protocol.AllowlistToken{
			{ID: "e1", Token: "spt_e1", Label: "e1"},
			{ID: "e2", Token: "spt_e2", Label: "e2"},
		},
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer integration-boot-hub-a")
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	e1 := register(t, srv.URL, "spt_e1", uuid.NewString(), "edge-1", protocol.RoleEdge)
	_ = register(t, srv.URL, "spt_e2", uuid.NewString(), "edge-2", protocol.RoleEdge)

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/netmap", nil)
	req.Header.Set("Authorization", "Bearer spt_e1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var nm protocol.NetmapResponse
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	if len(nm.Peers) != 1 || nm.Peers[0].PeerID != centerID {
		t.Fatalf("edge netmap: %+v", nm.Peers)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/netmap", nil)
	req.Header.Set("Authorization", "Bearer integration-boot-hub-a")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	if len(nm.Peers) != 2 {
		t.Fatalf("center netmap peers: %+v", nm.Peers)
	}
	_ = e1
}
