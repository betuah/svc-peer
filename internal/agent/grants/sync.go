package grants

import (
	"context"
	"fmt"
	"strings"

	"github.com/betuah/svc-peer/internal/protocol"
)

// HubSyncer is the subset of hub client calls needed for center→hub grant sync.
type HubSyncer interface {
	CreateGrant(ctx context.Context, req protocol.CreateGrantRequest) (*protocol.GrantInfo, error)
	RevokeGrant(ctx context.Context, id string) error
}

// SyncResult is the outcome of pushing local grants to the hub.
type SyncResult struct {
	HubID    string
	Upserted int
	IDs      []string
	Revoked  int
}

// PushToHub upserts active grants and revokes locally-revoked ids on the hub.
// Auth is the center client's bearer (center_bootstrap), matching allowlist sync.
func PushToHub(ctx context.Context, s *Store, hub HubSyncer) (SyncResult, error) {
	if s == nil {
		return SyncResult{}, fmt.Errorf("grant store is nil")
	}
	if hub == nil {
		return SyncResult{}, fmt.Errorf("hub syncer is nil")
	}

	upserted := 0
	ids := make([]string, 0)
	var hubID string
	for _, e := range s.Active() {
		info, err := hub.CreateGrant(ctx, protocol.CreateGrantRequest{
			ID:       e.ID,
			AgentAID: e.AgentAID,
			AgentBID: e.AgentBID,
		})
		if err != nil {
			return SyncResult{}, fmt.Errorf("create grant %s on hub: %w", e.ID, err)
		}
		if info != nil && hubID == "" {
			hubID = info.HubID
		}
		ids = append(ids, e.ID)
		upserted++
	}

	revoked := 0
	for _, id := range s.RevokedIDs() {
		if err := hub.RevokeGrant(ctx, id); err != nil {
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "grant not found") {
				continue
			}
			return SyncResult{}, fmt.Errorf("revoke %s on hub: %w", id, err)
		}
		revoked++
	}

	return SyncResult{
		HubID:    hubID,
		Upserted: upserted,
		IDs:      ids,
		Revoked:  revoked,
	}, nil
}
