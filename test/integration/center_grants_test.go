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
	"github.com/betuah/svc-peer/internal/agent/grants"
	"github.com/betuah/svc-peer/internal/agent/localapi"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

type integGrantMgr struct {
	store  *grants.Store
	client *agent.HubClient
}

func (m *integGrantMgr) ListGrants() ([]localapi.GrantView, error) {
	entries := m.store.List()
	out := make([]localapi.GrantView, 0, len(entries))
	for _, e := range entries {
		out = append(out, localapi.GrantView{
			ID: e.ID, AgentAID: e.AgentAID, AgentBID: e.AgentBID, Status: e.Status,
			CreatedAt: e.CreatedAt, RevokedAt: e.RevokedAt,
		})
	}
	return out, nil
}

func (m *integGrantMgr) CreateGrant(req localapi.CreateGrantRequest) (localapi.GrantView, error) {
	e, err := m.store.Add(req.ID, req.AgentAID, req.AgentBID)
	if err != nil {
		return localapi.GrantView{}, err
	}
	return localapi.GrantView{
		ID: e.ID, AgentAID: e.AgentAID, AgentBID: e.AgentBID, Status: e.Status, CreatedAt: e.CreatedAt,
	}, nil
}

func (m *integGrantMgr) RevokeGrant(id string) (localapi.GrantView, error) {
	e, err := m.store.Revoke(id)
	if err != nil {
		return localapi.GrantView{}, err
	}
	return localapi.GrantView{
		ID: e.ID, AgentAID: e.AgentAID, AgentBID: e.AgentBID, Status: e.Status,
		CreatedAt: e.CreatedAt, RevokedAt: e.RevokedAt,
	}, nil
}

func (m *integGrantMgr) SyncGrants(ctx context.Context) (localapi.GrantsSyncResult, error) {
	res, err := grants.PushToHub(ctx, m.store, m.client)
	if err != nil {
		return localapi.GrantsSyncResult{}, err
	}
	return localapi.GrantsSyncResult{
		HubID: res.HubID, Upserted: res.Upserted, IDs: res.IDs, Revoked: res.Revoked,
	}, nil
}

func TestCenterLocalGrantsCreateListRevokeSyncNetmap(t *testing.T) {
	h := newTestHub(t, "hub-center-grants")
	srv := httptest.NewServer(h.Router())
	defer srv.Close()

	boot := "integration-boot-hub-center-grants"
	centerID := uuid.NewString()
	_ = register(t, srv.URL, boot, centerID, "center", protocol.RoleCenter)

	edgeTokA := "spt_integ_grant_a"
	edgeTokB := "spt_integ_grant_b"
	syncAllowlist(t, srv.URL, boot, []protocol.AllowlistToken{
		{ID: "edge-a", Token: edgeTokA},
		{ID: "edge-b", Token: edgeTokB},
	})
	edgeA := uuid.NewString()
	edgeB := uuid.NewString()
	_ = register(t, srv.URL, edgeTokA, edgeA, "cam-a", protocol.RoleEdge)
	_ = register(t, srv.URL, edgeTokB, edgeB, "cam-b", protocol.RoleEdge)

	// Default: edge↔edge denied.
	if h.Netmap().AllowedPeer(edgeA, edgeB) {
		t.Fatal("edge↔edge must be denied before grant")
	}

	stateDir := t.TempDir()
	store, err := grants.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewHubClient(srv.URL, boot, false, nil)
	mgr := &integGrantMgr{store: store, client: client}
	view := &integLocalView{
		role: protocol.RoleCenter, agentID: centerID, hubID: "hub-center-grants",
		name: "center", hubConn: true, hubURL: srv.URL, token: boot,
	}
	local := httptest.NewServer(localapi.New(view, nil, mgr, nil).Handler())
	defer local.Close()

	body, err := json.Marshal(map[string]string{
		"id": "g-a2a", "agent_a_id": edgeA, "agent_b_id": edgeB,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(local.URL+"/local/grants", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("create: %s %s", res.Status, b)
	}
	var created localapi.GrantView
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID != "g-a2a" || created.Status != "active" {
		t.Fatalf("created=%+v", created)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "grants.json")); err != nil {
		t.Fatalf("expected durable grants.json: %v", err)
	}

	if !h.Netmap().AllowedPeer(edgeA, edgeB) {
		t.Fatal("granted pair must be allowed for punch/relay")
	}
	nm := h.Netmap().ForAgent(edgeA)
	found := false
	for _, p := range nm.Peers {
		if p.PeerID == edgeB {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("edge A netmap missing granted peer B: %+v", nm.Peers)
	}

	res, err = http.Get(local.URL + "/local/grants")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var listed localapi.GrantsResponse
	if err := json.NewDecoder(res.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Grants) != 1 || listed.Grants[0].Status != "active" {
		t.Fatalf("list=%+v", listed.Grants)
	}

	req, err := http.NewRequest(http.MethodDelete, local.URL+"/local/grants/g-a2a", nil)
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

	if h.Netmap().AllowedPeer(edgeA, edgeB) {
		t.Fatal("revoked pair must be denied again")
	}

	res, err = http.Post(local.URL+"/local/grants/sync", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("sync: %s %s", res.Status, b)
	}

	reloaded, err := grants.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := reloaded.Get("g-a2a")
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != grants.StatusRevoked {
		t.Fatalf("persisted status=%q", e.Status)
	}

	// Hub list empty after revoke.
	hubGrants, err := client.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hubGrants.Grants) != 0 {
		t.Fatalf("hub grants after revoke=%+v", hubGrants.Grants)
	}
}
