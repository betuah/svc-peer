package agent

import (
	"context"
	"fmt"

	"github.com/betuah/svc-peer/internal/agent/localapi"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
)

// localView implements localapi.View against the running Agent.
type localView struct {
	a *Agent
}

func (v localView) Role() string {
	v.a.mu.RLock()
	defer v.a.mu.RUnlock()
	if v.a.role != "" {
		return v.a.role
	}
	return v.a.cfg.Role
}

func (v localView) AgentID() string { return v.a.agentID }

func (v localView) HubID() string {
	v.a.mu.RLock()
	defer v.a.mu.RUnlock()
	if v.a.hubID != "" {
		return v.a.hubID
	}
	return v.a.cfg.HubID
}

func (v localView) Name() string { return v.a.cfg.Name }

func (v localView) OverlayIP() string {
	v.a.mu.RLock()
	defer v.a.mu.RUnlock()
	return v.a.overlayIP
}

func (v localView) CenterAgentID() string {
	v.a.mu.RLock()
	defer v.a.mu.RUnlock()
	return v.a.centerAgentID
}

func (v localView) HubConnected() bool {
	if v.a.client == nil {
		return false
	}
	return v.a.client.Connected()
}

func (v localView) WGBackend() string {
	if v.a.device == nil {
		return ""
	}
	return v.a.device.Backend()
}

func (v localView) NetmapPeers() ([]protocol.PeerConfig, map[string]string) {
	if v.a.paths == nil {
		return nil, map[string]string{}
	}
	return v.a.paths.SnapshotPeers()
}

func (v localView) ListHubAgents(ctx context.Context) (*protocol.AgentsListResponse, error) {
	return v.a.client.ListAgents(ctx)
}

func (v localView) PeerDeviceStats(publicKey string) (wgdev.PeerStats, bool, error) {
	if v.a.device == nil {
		return wgdev.PeerStats{}, false, nil
	}
	return v.a.device.PeerStats(publicKey)
}

func (v localView) ListAllowlist() ([]localapi.AllowlistEntryView, error) {
	if v.a.allowlist == nil {
		return nil, fmt.Errorf("allowlist store unavailable (center role required)")
	}
	entries := v.a.allowlist.List()
	out := make([]localapi.AllowlistEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToView(e, false))
	}
	return out, nil
}

func (v localView) CreateAllowlistEntry(req localapi.CreateAllowlistRequest) (localapi.AllowlistEntryView, error) {
	if v.a.allowlist == nil {
		return localapi.AllowlistEntryView{}, fmt.Errorf("allowlist store unavailable (center role required)")
	}
	e, err := v.a.allowlist.Add(req.ID, req.Token, req.Label, req.Tags)
	if err != nil {
		return localapi.AllowlistEntryView{}, err
	}
	return entryToView(e, true), nil
}

func (v localView) RevokeAllowlistEntry(id string) (localapi.AllowlistEntryView, error) {
	if v.a.allowlist == nil {
		return localapi.AllowlistEntryView{}, fmt.Errorf("allowlist store unavailable (center role required)")
	}
	e, err := v.a.allowlist.Revoke(id)
	if err != nil {
		return localapi.AllowlistEntryView{}, err
	}
	return entryToView(e, false), nil
}

func (v localView) SyncAllowlist(ctx context.Context) (localapi.AllowlistSyncResult, error) {
	return v.a.SyncAllowlistToHub(ctx)
}
