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

// TestHubTokenRegisterReconnectSmoke starts an in-process hub and checks
// mint -> first register (Agent ID) -> reconnect same identity.
func TestHubTokenRegisterReconnectSmoke(t *testing.T) {
	h, err := hub.New(hub.Config{
		ListenAddr:          ":0",
		HubSecret:           "integration-hub-secret",
		OverlayCIDR:         "10.88.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		STUNURLs:            []string{"stun:stun.l.google.com:19302"},
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/hub/tokens", bytes.NewReader([]byte(`{"label":"cam"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer integration-hub-secret")
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
	if tok.Token == "" {
		t.Fatal("empty token")
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(protocol.RegisterRequest{
		Name:      "cam-it",
		PublicKey: key.PublicKey().String(),
		Tags:      []string{"it"},
	})
	if err != nil {
		t.Fatal(err)
	}

	register := func() protocol.RegisterResponse {
		t.Helper()
		r, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/register", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+tok.Token)
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

	first := register()
	if first.AgentID == "" || first.OverlayIP == "" {
		t.Fatalf("first register incomplete: %+v", first)
	}
	second := register()
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
	if health.Status != "ok" {
		t.Fatalf("health: %+v", health)
	}
}
