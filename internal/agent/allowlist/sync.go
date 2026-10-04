package allowlist

import (
	"context"
	"fmt"
	"strings"

	"github.com/betuah/svc-peer/internal/protocol"
)

// HubSyncer is the subset of hub client calls needed for center→hub allowlist sync.
type HubSyncer interface {
	SyncAllowlist(ctx context.Context, tokens []protocol.AllowlistToken) (*protocol.AllowlistSyncResponse, error)
	RevokeToken(ctx context.Context, id string) error
}

// SyncResult is the outcome of pushing local allowlist state to the hub.
type SyncResult struct {
	HubID    string
	Upserted int
	IDs      []string
	Revoked  int
}

// PushToHub upserts active tokens and revokes locally-revoked ids on the hub cache.
func PushToHub(ctx context.Context, s *Store, hub HubSyncer) (SyncResult, error) {
	if s == nil {
		return SyncResult{}, fmt.Errorf("allowlist store is nil")
	}
	if hub == nil {
		return SyncResult{}, fmt.Errorf("hub syncer is nil")
	}
	syncResp, err := hub.SyncAllowlist(ctx, s.ActiveTokens())
	if err != nil {
		return SyncResult{}, err
	}
	revoked := 0
	for _, id := range s.RevokedIDs() {
		if err := hub.RevokeToken(ctx, id); err != nil {
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "token not found") {
				continue
			}
			return SyncResult{}, fmt.Errorf("revoke %s on hub: %w", id, err)
		}
		revoked++
	}
	ids := syncResp.IDs
	if ids == nil {
		ids = []string{}
	}
	return SyncResult{
		HubID:    syncResp.HubID,
		Upserted: syncResp.Upsert,
		IDs:      ids,
		Revoked:  revoked,
	}, nil
}
