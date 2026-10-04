package hub

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/betuah/svc-peer/internal/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testHub(t *testing.T, hubID string) *Hub {
	t.Helper()
	h, err := New(Config{
		ListenAddr:           ":0",
		HubID:                hubID,
		ManagementTokenSeed:  "mgmt-" + hubID,
		RelaySecret:          "relay-" + hubID,
		OverlayCIDR:          "10.10.0.0/16",
		DNSSuffix:            "peer.local",
		HeartbeatTimeoutSec:  45,
		HubEndpoint:          "127.0.0.1:51820",
		STUNURLs:             []string{"stun:stun.l.google.com:19302"},
		RelayURLs:            []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestManagementTokenOnlyCanMintAndGrant(t *testing.T) {
	h := testHub(t, "hub-main")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	// Agent token cannot mint.
	agentRec, agentRaw, err := h.Tokens().Mint(h.cfg.HubID, "cam", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = agentRec
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hub/tokens", bytes.NewReader([]byte(`{"label":"x"}`)))
	req.Header.Set("Authorization", "Bearer "+agentRaw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent mint: want 401/403, got %d", resp.StatusCode)
	}

	// Management token can mint.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/hub/tokens", bytes.NewReader([]byte(`{"label":"cam2"}`)))
	req.Header.Set("Authorization", "Bearer mgmt-hub-main")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("mgmt mint: %s %s", resp.Status, body)
	}

	// Register two agents.
	reg := func(name, tok string) string {
		t.Helper()
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(protocol.RegisterRequest{Name: name, PublicKey: k.PublicKey().String()})
		r, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/register", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
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
		return out.AgentID
	}

	aID := reg("cam-01", agentRaw)

	// Mint second agent via management.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/hub/tokens", bytes.NewReader([]byte(`{"label":"viewer"}`)))
	req.Header.Set("Authorization", "Bearer mgmt-hub-main")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tok2 protocol.TokenInfo
	_ = json.NewDecoder(resp.Body).Decode(&tok2)
	resp.Body.Close()
	bID := reg("viewer-01", tok2.Token)

	// Agent cannot grant.
	grantBody, _ := json.Marshal(protocol.CreateGrantRequest{AgentAID: aID, AgentBID: bID})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/hub/grants", bytes.NewReader(grantBody))
	req.Header.Set("Authorization", "Bearer "+agentRaw)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent grant: want 401/403, got %d", resp.StatusCode)
	}

	// Management can grant.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/hub/grants", bytes.NewReader(grantBody))
	req.Header.Set("Authorization", "Bearer mgmt-hub-main")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("mgmt grant: %s %s", resp.Status, body)
	}

	// Netmap for agent now includes peer.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/netmap", nil)
	req.Header.Set("Authorization", "Bearer "+agentRaw)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var nm protocol.NetmapResponse
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	if len(nm.Peers) != 2 {
		t.Fatalf("after grant expected 2 peers, got %d: %+v", len(nm.Peers), nm.Peers)
	}
}

func TestHubIsolationRejectsCrossHubToken(t *testing.T) {
	h1 := testHub(t, "hub-a")
	h2 := testHub(t, "hub-b")
	srv2 := httptest.NewServer(h2.Router())
	defer srv2.Close()

	_, raw, err := h1.Tokens().Mint("hub-a", "cam", nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(protocol.RegisterRequest{Name: "cam", PublicKey: k.PublicKey().String()})
	req, _ := http.NewRequest(http.MethodPost, srv2.URL+"/api/v1/agents/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("cross-hub token must not register on another hub")
	}
}

func TestTokenStoreRoleAndHubScope(t *testing.T) {
	s := NewTokenStore("hub-main")
	if err := s.SeedManagement("mgmt-id", "mgmt-secret"); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Lookup("mgmt-secret")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Role != RoleManagement || rec.HubID != "hub-main" {
		t.Fatalf("mgmt token: %+v", rec)
	}
	agent, raw, err := s.Mint("hub-main", "label", nil)
	if err != nil {
		t.Fatal(err)
	}
	if agent.Role != RoleAgent || agent.HubID != "hub-main" {
		t.Fatalf("agent token: %+v", agent)
	}
	if _, _, err := s.Mint("other-hub", "x", nil); err == nil {
		t.Fatal("mint for wrong hub_id must fail")
	}
	looked, err := s.Lookup(raw)
	if err != nil || looked.Role != RoleAgent {
		t.Fatalf("lookup agent: %+v %v", looked, err)
	}
}
