package agent

import (
	"context"
	"fmt"

	"github.com/betuah/svc-peer/internal/agent/allowlist"
	"github.com/betuah/svc-peer/internal/agent/localapi"
)

// SyncAllowlistToHub pushes active tokens via PUT /hub/allowlist and
// applies local revokes via DELETE /hub/tokens/{id}.
func (a *Agent) SyncAllowlistToHub(ctx context.Context) (localapi.AllowlistSyncResult, error) {
	if a.allowlist == nil {
		return localapi.AllowlistSyncResult{}, fmt.Errorf("allowlist store unavailable (center role required)")
	}
	res, err := allowlist.PushToHub(ctx, a.allowlist, a.client)
	if err != nil {
		return localapi.AllowlistSyncResult{}, err
	}
	return localapi.AllowlistSyncResult{
		HubID:    res.HubID,
		Upserted: res.Upserted,
		IDs:      res.IDs,
		Revoked:  res.Revoked,
	}, nil
}

func entryToView(e allowlist.Entry, includeSecret bool) localapi.AllowlistEntryView {
	v := localapi.AllowlistEntryView{
		ID:        e.ID,
		Label:     e.Label,
		Tags:      append([]string(nil), e.Tags...),
		Status:    e.Status,
		CreatedAt: e.CreatedAt,
		RevokedAt: e.RevokedAt,
	}
	if includeSecret {
		v.Token = e.Token
	}
	return v
}
