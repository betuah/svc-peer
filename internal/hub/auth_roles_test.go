package hub

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testHub(t *testing.T, hubID string) *Hub {
	t.Helper()
	h, err := New(Config{
		ListenAddr:          ":0",
		HubID:               hubID,
		CenterBootstrap:     "boot-" + hubID,
		ManagementTokenSeed: "mgmt-" + hubID,
		RelaySecret:         "relay-" + hubID,
		OverlayCIDR:         "10.10.0.0/16",
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

func registerLocal(t *testing.T, srvURL, bearer, agentID, name, role string) protocol.RegisterResponse {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(protocol.RegisterRequest{
		AgentID: agentID, Name: name, PublicKey: k.PublicKey().String(), Role: role,
	})
	r, _ := http.NewRequest(http.MethodPost, srvURL+"/api/v1/agents/register", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	r.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("register %s: %s %s", name, res.Status, b)
	}
	var out protocol.RegisterResponse
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

func TestCenterBootstrapAndAllowlistSync(t *testing.T) {
	h := testHub(t, "hub-main")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	centerID := uuid.NewString()
	c := registerLocal(t, srv.URL, "boot-hub-main", centerID, "center", protocol.RoleCenter)
	if c.Role != protocol.RoleCenter || c.AgentID != centerID {
		t.Fatalf("center: %+v", c)
	}
	if len(c.Peers) != 0 {
		t.Fatalf("center with no edges should have 0 peers, got %d", len(c.Peers))
	}

	// Second center rejected.
	other := uuid.NewString()
	k, _ := wgtypes.GeneratePrivateKey()
	body, _ := json.Marshal(protocol.RegisterRequest{
		AgentID: other, Name: "c2", PublicKey: k.PublicKey().String(), Role: protocol.RoleCenter,
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer boot-hub-main")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second center: want 409, got %d", resp.StatusCode)
	}

	// Center syncs edge token.
	edgeTok := "spt_edge_join_token_test_01"
	syncBody, _ := json.Marshal(protocol.AllowlistSyncRequest{Tokens: []protocol.AllowlistToken{
		{ID: "edge-1", Token: edgeTok, Label: "cam"},
	}})
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer boot-hub-main")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("allowlist: %s %s", resp.Status, b)
	}

	edgeID := uuid.NewString()
	e := registerLocal(t, srv.URL, edgeTok, edgeID, "cam-01", protocol.RoleEdge)
	if e.Role != protocol.RoleEdge || len(e.Peers) != 1 || e.Peers[0].PeerID != centerID {
		t.Fatalf("edge register/netmap: %+v", e)
	}
	if e.CenterAgentID != centerID {
		t.Fatalf("center_agent_id: %s", e.CenterAgentID)
	}

	// Edge cannot sync allowlist.
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer "+edgeTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("edge must not sync allowlist")
	}
}

func TestHubIsolationRejectsCrossHubToken(t *testing.T) {
	h1 := testHub(t, "hub-a")
	h2 := testHub(t, "hub-b")
	srv1 := httptest.NewServer(h1.Router())
	defer srv1.Close()
	srv2 := httptest.NewServer(h2.Router())
	defer srv2.Close()

	registerLocal(t, srv1.URL, "boot-hub-a", uuid.NewString(), "center", protocol.RoleCenter)
	syncBody, _ := json.Marshal(protocol.AllowlistSyncRequest{Tokens: []protocol.AllowlistToken{
		{ID: "e", Token: "spt_cross_hub_tok", Label: "x"},
	}})
	req, _ := http.NewRequest(http.MethodPut, srv1.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer boot-hub-a")
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	k, _ := wgtypes.GeneratePrivateKey()
	body, _ := json.Marshal(protocol.RegisterRequest{
		AgentID: uuid.NewString(), Name: "x", PublicKey: k.PublicKey().String(), Role: protocol.RoleEdge,
	})
	req, _ = http.NewRequest(http.MethodPost, srv2.URL+"/api/v1/agents/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer spt_cross_hub_tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("cross-hub token must not register")
	}
}
