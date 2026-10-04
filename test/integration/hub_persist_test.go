//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

func TestHubStateSurvivesRestartAndCenterResync(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "hub-state.json")
	cfg := hub.Config{
		ListenAddr:          ":0",
		HubID:               "hub-persist-it",
		CenterBootstrap:     "integration-boot-persist",
		ManagementTokenSeed: "integration-mgmt-persist",
		RelaySecret:         "integration-relay-persist",
		OverlayCIDR:         "10.77.0.0/16",
		DNSSuffix:           "peer.local",
		HeartbeatTimeoutSec: 45,
		STUNURLs:            []string{"stun:stun.l.google.com:19302"},
		RelayURLs:           []string{"udp://127.0.0.1:3478"},
		StatePath:           statePath,
	}

	h1, err := hub.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv1 := httptest.NewServer(h1.Router())
	defer srv1.Close()

	centerID := uuid.NewString()
	center := register(t, srv1.URL, "integration-boot-persist", centerID, "center", protocol.RoleCenter)
	edgeTok := "spt_persist_it_edge"
	syncBody, _ := json.Marshal(protocol.AllowlistSyncRequest{
		Tokens: []protocol.AllowlistToken{{ID: "seed-edge", Token: edgeTok, Label: "cam"}},
	})
	req, _ := http.NewRequest(http.MethodPut, srv1.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer integration-boot-persist")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlist sync: %d", resp.StatusCode)
	}

	edgeID := uuid.NewString()
	edge := register(t, srv1.URL, edgeTok, edgeID, "cam-persist", protocol.RoleEdge)
	srv1.Close()

	// Restart hub from the same state file.
	h2, err := hub.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(h2.Router())
	defer srv2.Close()

	if h2.Registry().OnlineCount() != 0 {
		t.Fatalf("presence must be ephemeral; online=%d", h2.Registry().OnlineCount())
	}
	got, err := h2.Registry().Get(edgeID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Online || got.OverlayIP.String() != edge.OverlayIP {
		t.Fatalf("restored edge: online=%v ip=%s want %s", got.Online, got.OverlayIP, edge.OverlayIP)
	}
	if h2.Registry().CenterAgentID() != centerID {
		t.Fatalf("center id after restart: %s", h2.Registry().CenterAgentID())
	}

	// Edge can re-register using cached allowlist before center re-sync.
	again := register(t, srv2.URL, edgeTok, edgeID, "cam-persist", protocol.RoleEdge)
	if again.OverlayIP != edge.OverlayIP || again.AgentID != edgeID {
		t.Fatalf("edge reconnect: %+v", again)
	}

	// Center reconnects and re-syncs allowlist (source of truth).
	_ = register(t, srv2.URL, "integration-boot-persist", centerID, "center", protocol.RoleCenter)
	syncBody, _ = json.Marshal(protocol.AllowlistSyncRequest{
		Tokens: []protocol.AllowlistToken{
			{ID: "seed-edge", Token: edgeTok, Label: "cam"},
			{ID: "seed-edge-2", Token: "spt_persist_it_edge_2", Label: "cam-2"},
		},
	})
	req, _ = http.NewRequest(http.MethodPut, srv2.URL+"/hub/allowlist", bytes.NewReader(syncBody))
	req.Header.Set("Authorization", "Bearer integration-boot-persist")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("center re-sync: %s %s", resp.Status, body)
	}

	edge2ID := uuid.NewString()
	e2 := register(t, srv2.URL, "spt_persist_it_edge_2", edge2ID, "cam-2", protocol.RoleEdge)
	if e2.AgentID != edge2ID {
		t.Fatalf("second edge: %+v", e2)
	}

	// Third hub boot keeps both edges + updated allowlist.
	srv2.Close()
	h3, err := hub.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h3.Tokens().Lookup("spt_persist_it_edge_2"); err != nil {
		t.Fatalf("persisted re-synced token: %v", err)
	}
	if _, err := h3.Registry().Get(edge2ID); err != nil {
		t.Fatalf("persisted edge2: %v", err)
	}
	_ = center
}
