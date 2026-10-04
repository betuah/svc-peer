package hub

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
)

var (
	ErrAgentNotFound     = errors.New("agent not found")
	ErrPublicKeyUsed     = errors.New("public key already bound to another agent")
	ErrAgentIDCollision  = errors.New("agent_id already bound to a different identity")
	ErrCenterExists      = errors.New("center already claimed for this hub_id")
	ErrCenterRequired    = errors.New("center not registered yet")
	ErrInvalidAgentID    = errors.New("agent_id is required")
	ErrInvalidRole       = errors.New("invalid role")
)

// Agent is a registered peer identity in the hub registry.
type Agent struct {
	ID           string
	HubID        string
	Role         string // center | edge
	Name         string
	PublicKey    string
	OverlayIP    netip.Prefix
	DNSName      string
	Tags         []string
	Capabilities []string
	Platform     string
	WGBackend    string
	Online       bool
	LastSeen     time.Time
	Endpoints    []protocol.Endpoint
	TokenID      string // empty for center (bootstrap); edge join token id otherwise
}

// Registry tracks agents, presence, roles, and IPAM for one hub_id.
type Registry struct {
	mu           sync.RWMutex
	hubID        string
	agents       map[string]*Agent
	byPubKey     map[string]string
	centerID     string
	ipam         *IPAM
	dnsSuffix    string
	revision     uint64
	hbTimeout    time.Duration
}

// NewRegistry creates a registry with IPAM from overlayCIDR, scoped to hubID.
func NewRegistry(hubID, overlayCIDR, dnsSuffix string, heartbeatTimeout time.Duration) (*Registry, error) {
	if hubID == "" {
		return nil, errors.New("hub_id is required")
	}
	ipam, err := NewIPAM(overlayCIDR)
	if err != nil {
		return nil, err
	}
	if dnsSuffix == "" {
		dnsSuffix = "peer.local"
	}
	return &Registry{
		hubID:     hubID,
		agents:    make(map[string]*Agent),
		byPubKey:  make(map[string]string),
		ipam:      ipam,
		dnsSuffix: dnsSuffix,
		hbTimeout: heartbeatTimeout,
	}, nil
}

// HubID returns the registry's hub scope.
func (r *Registry) HubID() string { return r.hubID }

// CenterAgentID returns the sole center agent id, or empty if none.
func (r *Registry) CenterAgentID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.centerID
}

// RegisterPresented creates or reconnects using a locally generated agent_id.
// Hub does not mint Agent IDs. tokenID is empty for center bootstrap path.
func (r *Registry) RegisterPresented(agentID, tokenID, role string, req protocol.RegisterRequest) (*Agent, bool, error) {
	if agentID == "" {
		return nil, false, ErrInvalidAgentID
	}
	switch role {
	case protocol.RoleCenter, protocol.RoleEdge:
	default:
		return nil, false, ErrInvalidRole
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()

	if existing, ok := r.agents[agentID]; ok {
		// Collision: same agent_id already bound to a different credential.
		if tokenID != "" && existing.TokenID != "" && existing.TokenID != tokenID {
			return nil, false, ErrAgentIDCollision
		}
		if existing.Role != role {
			return nil, false, ErrAgentIDCollision
		}
		if role == protocol.RoleCenter && r.centerID != "" && r.centerID != agentID {
			return nil, false, ErrCenterExists
		}
		if err := r.updateExistingLocked(existing, req, now); err != nil {
			return nil, false, err
		}
		cp := *existing
		return &cp, false, nil
	}

	// First register for this agent_id.
	if role == protocol.RoleCenter {
		if r.centerID != "" {
			return nil, false, ErrCenterExists
		}
	} else if r.centerID == "" {
		// Edges may register before center for allowlist caching, but netmap needs center.
		// Allow edge register without center (they'll get empty peers until center joins).
	}

	if req.PublicKey == "" {
		return nil, false, errors.New("public_key is required")
	}
	if req.Name == "" {
		return nil, false, errors.New("name is required")
	}
	if other, taken := r.byPubKey[req.PublicKey]; taken {
		return nil, false, errors.New("public key already bound to agent " + other)
	}

	ip, err := r.ipam.Allocate()
	if err != nil {
		return nil, false, err
	}

	a := &Agent{
		ID:           agentID,
		HubID:        r.hubID,
		Role:         role,
		Name:         req.Name,
		PublicKey:    req.PublicKey,
		OverlayIP:    netip.PrefixFrom(ip, 32),
		DNSName:      dnsName(req.Name, r.dnsSuffix),
		Tags:         append([]string(nil), req.Tags...),
		Capabilities: append([]string(nil), req.Capabilities...),
		Platform:     req.Platform,
		WGBackend:    req.WGBackend,
		Online:       true,
		LastSeen:     now,
		TokenID:      tokenID,
	}
	r.agents[a.ID] = a
	r.byPubKey[a.PublicKey] = a.ID
	if role == protocol.RoleCenter {
		r.centerID = a.ID
	}
	r.revision++
	cp := *a
	return &cp, true, nil
}

func (r *Registry) updateExistingLocked(a *Agent, req protocol.RegisterRequest, now time.Time) error {
	if req.PublicKey != "" && req.PublicKey != a.PublicKey {
		if other, taken := r.byPubKey[req.PublicKey]; taken && other != a.ID {
			return ErrPublicKeyUsed
		}
		delete(r.byPubKey, a.PublicKey)
		a.PublicKey = req.PublicKey
		r.byPubKey[a.PublicKey] = a.ID
	}
	if req.Name != "" {
		a.Name = req.Name
		a.DNSName = dnsName(req.Name, r.dnsSuffix)
	}
	if req.Tags != nil {
		a.Tags = append([]string(nil), req.Tags...)
	}
	if req.Capabilities != nil {
		a.Capabilities = append([]string(nil), req.Capabilities...)
	}
	if req.Platform != "" {
		a.Platform = req.Platform
	}
	if req.WGBackend != "" {
		a.WGBackend = req.WGBackend
	}
	a.Online = true
	a.LastSeen = now
	r.revision++
	return nil
}

// Heartbeat marks an agent online and updates last seen.
func (r *Registry) Heartbeat(agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	a.Online = true
	a.LastSeen = time.Now().UTC()
	return nil
}

// SetOffline marks an agent offline (WS disconnect or timeout).
func (r *Registry) SetOffline(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[agentID]; ok {
		a.Online = false
	}
}

// SweepOffline marks agents past heartbeat timeout as offline.
func (r *Registry) SweepOffline() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var flipped []string
	cutoff := time.Now().UTC().Add(-r.hbTimeout)
	for id, a := range r.agents {
		if a.Online && a.LastSeen.Before(cutoff) {
			a.Online = false
			flipped = append(flipped, id)
		}
	}
	return flipped
}

// UpdateEndpoints stores last reported endpoints for an agent.
func (r *Registry) UpdateEndpoints(agentID string, endpoints []protocol.Endpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	a.Endpoints = protocol.RankEndpoints(endpoints)
	a.LastSeen = time.Now().UTC()
	a.Online = true
	r.revision++
	return nil
}

// Get returns an agent by ID.
func (r *Registry) Get(id string) (*Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	cp := *a
	return &cp, nil
}

// List returns agents on this hub, optionally only online.
func (r *Registry) List(onlineOnly bool) []protocol.AgentSummary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]protocol.AgentSummary, 0, len(r.agents))
	for _, a := range r.agents {
		if onlineOnly && !a.Online {
			continue
		}
		out = append(out, protocol.AgentSummary{
			ID:           a.ID,
			Name:         a.Name,
			Role:         a.Role,
			OverlayIP:    a.OverlayIP.Addr().String(),
			DNSName:      a.DNSName,
			Tags:         append([]string(nil), a.Tags...),
			Capabilities: append([]string(nil), a.Capabilities...),
			Online:       a.Online,
			LastSeen:     a.LastSeen,
		})
	}
	return out
}

// BumpRevision increments the netmap revision.
func (r *Registry) BumpRevision() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revision++
	return r.revision
}

// Revision returns the current netmap revision.
func (r *Registry) Revision() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revision
}

// OnlineCount returns connected (online) agents.
func (r *Registry) OnlineCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, a := range r.agents {
		if a.Online {
			n++
		}
	}
	return n
}

// SnapshotAgents returns a copy of all agents.
func (r *Registry) SnapshotAgents() []*Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		cp := *a
		out = append(out, &cp)
	}
	return out
}

// RestoreAgents loads durable membership from disk. Agents are restored offline;
// presence requires a fresh register/heartbeat. Overlay IPs are reserved in IPAM.
func (r *Registry) RestoreAgents(agents []Agent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, in := range agents {
		if in.ID == "" {
			return errors.New("restore agent: agent_id required")
		}
		switch in.Role {
		case protocol.RoleCenter, protocol.RoleEdge:
		default:
			return ErrInvalidRole
		}
		if _, exists := r.agents[in.ID]; exists {
			return errors.New("restore agent: duplicate agent_id " + in.ID)
		}
		if in.PublicKey == "" {
			return errors.New("restore agent: public_key required for " + in.ID)
		}
		if other, taken := r.byPubKey[in.PublicKey]; taken {
			return errors.New("restore agent: public key already bound to " + other)
		}
		if !in.OverlayIP.IsValid() {
			return errors.New("restore agent: overlay_ip required for " + in.ID)
		}
		if err := r.ipam.Reserve(in.OverlayIP.Addr()); err != nil {
			return err
		}
		a := &Agent{
			ID:           in.ID,
			HubID:        r.hubID,
			Role:         in.Role,
			Name:         in.Name,
			PublicKey:    in.PublicKey,
			OverlayIP:    in.OverlayIP,
			DNSName:      in.DNSName,
			Tags:         append([]string(nil), in.Tags...),
			Capabilities: append([]string(nil), in.Capabilities...),
			Platform:     in.Platform,
			WGBackend:    in.WGBackend,
			Online:       false, // presence is ephemeral
			TokenID:      in.TokenID,
		}
		if a.DNSName == "" && a.Name != "" {
			a.DNSName = dnsName(a.Name, r.dnsSuffix)
		}
		r.agents[a.ID] = a
		r.byPubKey[a.PublicKey] = a.ID
		if a.Role == protocol.RoleCenter {
			if r.centerID != "" && r.centerID != a.ID {
				return ErrCenterExists
			}
			r.centerID = a.ID
		}
		r.revision++
	}
	return nil
}

func dnsName(name, suffix string) string {
	return name + "." + suffix
}
