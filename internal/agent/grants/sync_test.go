package grants

import (
	"context"
	"fmt"
	"testing"

	"github.com/betuah/svc-peer/internal/protocol"
)

type fakeHub struct {
	grants  map[string]protocol.GrantInfo
	creates int
	revokes int
}

func (f *fakeHub) CreateGrant(_ context.Context, req protocol.CreateGrantRequest) (*protocol.GrantInfo, error) {
	if f.grants == nil {
		f.grants = map[string]protocol.GrantInfo{}
	}
	f.creates++
	id := req.ID
	if id == "" {
		id = fmt.Sprintf("hub-%d", f.creates)
	}
	info := protocol.GrantInfo{
		ID: id, HubID: "hub-main", AgentAID: req.AgentAID, AgentBID: req.AgentBID,
	}
	f.grants[id] = info
	return &info, nil
}

func (f *fakeHub) RevokeGrant(_ context.Context, id string) error {
	if _, ok := f.grants[id]; !ok {
		return fmt.Errorf("DELETE /hub/grants/%s: 404: grant not found", id)
	}
	delete(f.grants, id)
	f.revokes++
	return nil
}

func TestPushToHubCreateAndRevoke(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("g1", "e1", "e2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("g2", "e3", "e4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke("g2"); err != nil {
		t.Fatal(err)
	}

	hub := &fakeHub{grants: map[string]protocol.GrantInfo{
		"g2": {ID: "g2", HubID: "hub-main", AgentAID: "e3", AgentBID: "e4"},
	}}
	res, err := PushToHub(context.Background(), s, hub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Upserted != 1 || res.Revoked != 1 || res.HubID != "hub-main" {
		t.Fatalf("sync=%+v", res)
	}
	if _, ok := hub.grants["g1"]; !ok {
		t.Fatal("expected g1 on hub")
	}
	if _, ok := hub.grants["g2"]; ok {
		t.Fatal("g2 should be revoked on hub")
	}
}
