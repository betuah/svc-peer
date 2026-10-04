//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestHub(t *testing.T, hubID string) *hub.Hub {
	t.Helper()
	h, err := hub.New(hub.Config{
		ListenAddr:          ":0",
		HubID:               hubID,
		ManagementTokenSeed: "integration-mgmt-" + hubID,
		RelaySecret:         "integration-relay-" + hubID,
		OverlayCIDR:         "10.88.0.0/16",
		DNSSuffix:           "peer.local",
		HubEndpoint:         "127.0.0.1:51820",
		HeartbeatTimeoutSec: 45,
		STUNURLs:            []string{"stun:stun.l.google.com:19302"},
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mintAgentToken(t *testing.T, srvURL, mgmt string) protocol.TokenInfo {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+"/hub/tokens", bytes.NewReader([]byte(`{"label":"cam"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+mgmt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("mint: %s %s", resp.Status, body)
	}
	var tok protocol.TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func registerAgent(t *testing.T, srvURL, token, name string) protocol.RegisterResponse {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(protocol.RegisterRequest{
		Name:      name,
		PublicKey: key.PublicKey().String(),
		Tags:      []string{"it"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, srvURL+"/api/v1/agents/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
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

// TestHubTokenRegisterReconnectSmoke starts an in-process hub and checks
// mint -> first register (Agent ID) -> reconnect same identity; default ACL hub-only peers.
func TestHubTokenRegisterReconnectSmoke(t *testing.T) {
	h := newTestHub(t, "hub-it")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	tok := mintAgentToken(t, srv.URL, "integration-mgmt-hub-it")
	if tok.Token == "" || tok.HubID != "hub-it" || tok.Role != "agent" {
		t.Fatalf("token: %+v", tok)
	}

	first := registerAgent(t, srv.URL, tok.Token, "cam-it")
	if first.AgentID == "" || first.OverlayIP == "" || first.HubID != "hub-it" {
		t.Fatalf("first register incomplete: %+v", first)
	}
	if len(first.Peers) != 1 || first.Peers[0].PeerID != "hub" {
		t.Fatalf("default ACL peers: %+v", first.Peers)
	}
	second := registerAgent(t, srv.URL, tok.Token, "cam-it")
	if second.AgentID != first.AgentID {
		t.Fatalf("agent id changed: %s -> %s", first.AgentID, second.AgentID)
	}
	if second.OverlayIP != first.OverlayIP {
		t.Fatalf("overlay ip changed: %s -> %s", first.OverlayIP, second.OverlayIP)
	}

	hres, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer hres.Body.Close()
	var health protocol.HealthResponse
	if err := json.NewDecoder(hres.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "ok" || health.HubID != "hub-it" {
		t.Fatalf("health: %+v", health)
	}
}

func TestHubIsolationAndGrantACL(t *testing.T) {
	h1 := newTestHub(t, "hub-a")
	h2 := newTestHub(t, "hub-b")
	srv1 := httptest.NewServer(h1.Router())
	defer srv1.Close()
	srv2 := httptest.NewServer(h2.Router())
	defer srv2.Close()

	tokA := mintAgentToken(t, srv1.URL, "integration-mgmt-hub-a")
	// Cross-hub: token from hub-a must not register on hub-b.
	key, _ := wgtypes.GeneratePrivateKey()
	body, _ := json.Marshal(protocol.RegisterRequest{Name: "x", PublicKey: key.PublicKey().String()})
	req, _ := http.NewRequest(http.MethodPost, srv2.URL+"/api/v1/agents/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokA.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("cross-hub register must fail")
	}

	a := registerAgent(t, srv1.URL, tokA.Token, "cam-a")
	tokB := mintAgentToken(t, srv1.URL, "integration-mgmt-hub-a")
	b := registerAgent(t, srv1.URL, tokB.Token, "viewer-b")

	// Default: no A2A peer.
	req, _ = http.NewRequest(http.MethodGet, srv1.URL+"/api/v1/netmap", nil)
	req.Header.Set("Authorization", "Bearer "+tokA.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var nm protocol.NetmapResponse
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	resp.Body.Close()
	if len(nm.Peers) != 1 || nm.Peers[0].PeerID != "hub" {
		t.Fatalf("pre-grant netmap: %+v", nm.Peers)
	}

	// Agent cannot grant.
	grantBody, _ := json.Marshal(protocol.CreateGrantRequest{AgentAID: a.AgentID, AgentBID: b.AgentID})
	req, _ = http.NewRequest(http.MethodPost, srv1.URL+"/hub/grants", bytes.NewReader(grantBody))
	req.Header.Set("Authorization", "Bearer "+tokA.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("agent must not grant")
	}

	// Management grants A2A.
	req, _ = http.NewRequest(http.MethodPost, srv1.URL+"/hub/grants", bytes.NewReader(grantBody))
	req.Header.Set("Authorization", "Bearer integration-mgmt-hub-a")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("grant: %s %s", resp.Status, body)
	}

	req, _ = http.NewRequest(http.MethodGet, srv1.URL+"/api/v1/netmap", nil)
	req.Header.Set("Authorization", "Bearer "+tokA.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	if len(nm.Peers) != 2 {
		t.Fatalf("post-grant netmap peers: %+v", nm.Peers)
	}

	// Discovery includes online status on this hub only.
	req, _ = http.NewRequest(http.MethodGet, srv1.URL+"/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+tokA.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list protocol.AgentsListResponse
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if list.HubID != "hub-a" || len(list.Agents) != 2 {
		t.Fatalf("list: %+v", list)
	}
}
