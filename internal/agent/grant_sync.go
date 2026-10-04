package agent

import (
	"context"
	"fmt"

	"github.com/betuah/svc-peer/internal/agent/grants"
	"github.com/betuah/svc-peer/internal/agent/localapi"
)

// SyncGrantsToHub pushes active grants via POST /hub/grants and
// applies local revokes via DELETE /hub/grants/{id}.
func (a *Agent) SyncGrantsToHub(ctx context.Context) (localapi.GrantsSyncResult, error) {
	if a.grants == nil {
		return localapi.GrantsSyncResult{}, fmt.Errorf("grant store unavailable (center role required)")
	}
	res, err := grants.PushToHub(ctx, a.grants, a.client)
	if err != nil {
		return localapi.GrantsSyncResult{}, err
	}
	return localapi.GrantsSyncResult{
		HubID:    res.HubID,
		Upserted: res.Upserted,
		IDs:      res.IDs,
		Revoked:  res.Revoked,
	}, nil
}

func grantToView(e grants.Entry) localapi.GrantView {
	return localapi.GrantView{
		ID:        e.ID,
		AgentAID:  e.AgentAID,
		AgentBID:  e.AgentBID,
		Status:    e.Status,
		CreatedAt: e.CreatedAt,
		RevokedAt: e.RevokedAt,
	}
}
