//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/betuah/svc-peer/internal/agent"
	"github.com/betuah/svc-peer/internal/agent/allowlist"
	"github.com/betuah/svc-peer/internal/agent/localapi"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type integAllowlistMgr struct {
	store  *allowlist.Store
	client *agent.HubClient
}

func (m *integAllowlistMgr) ListAllowlist() ([]localapi.AllowlistEntryView, error) {
	entries := m.store.List()
	out := make([]localapi.AllowlistEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, localapi.AllowlistEntryView{
			ID: e.ID, Label: e.Label, Tags: e.Tags, Status: e.Status,
			CreatedAt: e.CreatedAt, RevokedAt: e.RevokedAt,
		})
	}
	return out, nil
}

func (m *integAllowlistMgr) CreateAllowlistEntry(req localapi.CreateAllowlistRequest) (localapi.AllowlistEntryView, error) {
	e, err := m.store.Add(req.ID, req.Token, req.Label, req.Tags)
	if err != nil {
		return localapi.AllowlistEntryView{}, err
	}
	return localapi.AllowlistEntryView{
		ID: e.ID, Token: e.Token, Label: e.Label, Tags: e.Tags, Status: e.Status, CreatedAt: e.CreatedAt,
	}, nil
}

func (m *integAllowlistMgr) RevokeAllowlistEntry(id string) (localapi.AllowlistEntryView, error) {
	e, err := m.store.Revoke(id)
	if err != nil {
		return localapi.AllowlistEntryView{}, err
	}
	return localapi.AllowlistEntryView{
		ID: e.ID, Label: e.Label, Tags: e.Tags, Status: e.Status, CreatedAt: e.CreatedAt, RevokedAt: e.RevokedAt,
	}, nil
}

func (m *integAllowlistMgr) SyncAllowlist(ctx context.Context) (localapi.AllowlistSyncResult, error) {
	res, err := allowlist.PushToHub(ctx, m.store, m.client)
	if err != nil {
		return localapi.AllowlistSyncResult{}, err
	}
	return localapi.AllowlistSyncResult{
		HubID: res.HubID, Upserted: res.Upserted, IDs: res.IDs, Revoked: res.Revoked,
	}, nil
}

func TestCenterLocalAllowlistCreateListRevokeSync(t *testing.T) {
	h := newTestHub(t, "hub-center-allowlist")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	boot := "integration-boot-hub-center-allowlist"
	centerID := uuid.NewString()
	_ = register(t, srv.URL, boot, centerID, "center", protocol.RoleCenter)

	stateDir := t.TempDir()
	store, err := allowlist.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewHubClient(srv.URL, boot, false, nil)
	mgr := &integAllowlistMgr{store: store, client: client}
	view := &integLocalView{
		role: protocol.RoleCenter, agentID: centerID, hubID: "hub-center-allowlist",
		name: "center", hubConn: true, hubURL: srv.URL, token: boot,
	}
	local := httptest.NewServer(localapi.New(view, mgr, nil, nil).Handler())
	defer local.Close()

	// Create join token via local API (secret returned once).
	body := []byte(`{"id":"cam-01","label":"warehouse-cam","tags":["warehouse"]}`)
	res, err := http.Post(local.URL+"/local/allowlist", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("create: %s %s", res.Status, b)
	}
	var created localapi.AllowlistEntryView
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.ID != "cam-01" {
		t.Fatalf("created=%+v", created)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "allowlist.json")); err != nil {
		t.Fatalf("expected durable allowlist.json: %v", err)
	}

	// List redacts secret.
	res, err = http.Get(local.URL + "/local/allowlist")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var listed localapi.AllowlistResponse
	if err := json.NewDecoder(res.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].Token != "" || listed.Entries[0].Status != "active" {
		t.Fatalf("list=%+v", listed.Entries)
	}

	// Edge can enroll with minted token (synced to hub on create).
	edgeID := uuid.NewString()
	edge := register(t, srv.URL, created.Token, edgeID, "cam", protocol.RoleEdge)
	if edge.CenterAgentID != centerID {
		t.Fatalf("center_agent_id=%q", edge.CenterAgentID)
	}

	// Revoke and force sync.
	req, err := http.NewRequest(http.MethodDelete, local.URL+"/local/allowlist/cam-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("revoke: %s %s", res.Status, b)
	}

	res, err = http.Post(local.URL+"/local/allowlist/sync", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("sync: %s %s", res.Status, b)
	}

	// New edge cannot enroll with revoked token.
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bodyReg, err := json.Marshal(protocol.RegisterRequest{
		AgentID: uuid.NewString(), Name: "cam2", Role: protocol.RoleEdge,
		PublicKey: key.PublicKey().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/register", bytes.NewReader(bodyReg))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+created.Token)
	r.Header.Set("Content-Type", "application/json")
	res, err = http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("revoked token must not register a new edge")
	}

	// Reload store from disk — revoke persisted.
	reloaded, err := allowlist.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := reloaded.Get("cam-01")
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != allowlist.StatusRevoked {
		t.Fatalf("persisted status=%q", e.Status)
	}
}
