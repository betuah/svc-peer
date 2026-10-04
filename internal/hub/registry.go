package hub

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

var (
	ErrAgentNotFound = errors.New("agent not found")
	ErrPublicKeyUsed = errors.New("public key already bound to another agent")
)

// Agent is a registered peer identity in the hub registry.
type Agent struct {
	ID           string
	Name         string
	PublicKey    string
	OverlayIP    netip.Prefix // /32 assignment
	DNSName      string
	Tags         []string
	Capabilities []string
	Platform     string
	WGBackend    string
	Online       bool
	LastSeen     time.Time
	Endpoints    []protocol.Endpoint
	TokenID      string
}

// Registry tracks agents, presence, and IPAM from the configured overlay CIDR.
type Registry struct {
	mu         sync.RWMutex
	agents     map[string]*Agent
	byPubKey   map[string]string // pubkey → agent ID
	ipam       *IPAM
	dnsSuffix  string
	revision   uint64
	hbTimeout  time.Duration
}

// NewRegistry creates a registry with IPAM from overlayCIDR.
func NewRegistry(overlayCIDR, dnsSuffix string, heartbeatTimeout time.Duration) (*Registry, error) {
	ipam, err := NewIPAM(overlayCIDR)
	if err != nil {
		return nil, err
	}
	if dnsSuffix == "" {
		dnsSuffix = "peer.local"
	}
	return &Registry{
		agents:    make(map[string]*Agent),
		byPubKey:  make(map[string]string),
		ipam:      ipam,
		dnsSuffix: dnsSuffix,
		hbTimeout: heartbeatTimeout,
	}, nil
}

// RegisterFirstOrReconnect creates Agent ID on first register, or restores the same agent.
func (r *Registry) RegisterFirstOrReconnect(tokenID, existingAgentID string, req protocol.RegisterRequest) (*Agent, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()

	// Reconnect path: token already bound.
	if existingAgentID != "" {
		a, ok := r.agents[existingAgentID]
		if !ok {
			return nil, false, ErrAgentNotFound
		}
		if req.PublicKey != "" && req.PublicKey != a.PublicKey {
			if other, taken := r.byPubKey[req.PublicKey]; taken && other != a.ID {
				return nil, false, ErrPublicKeyUsed
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
		cp := *a
		return &cp, false, nil
	}

	// First successful register for this token.
	if req.PublicKey == "" {
		return nil, false, errors.New("public_key is required")
	}
	if req.Name == "" {
		return nil, false, errors.New("name is required")
	}
	if other, taken := r.byPubKey[req.PublicKey]; taken {
		return nil, false, fmtPubkeyTaken(other)
	}

	ip, err := r.ipam.Allocate()
	if err != nil {
		return nil, false, err
	}

	a := &Agent{
		ID:           uuid.NewString(),
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
	r.revision++
	cp := *a
	return &cp, true, nil
}

func fmtPubkeyTaken(other string) error {
	return errors.New("public key already bound to agent " + other)
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

// SweepOffline marks agents past heartbeat timeout as offline. Returns IDs flipped.
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
	a.Endpoints = append([]protocol.Endpoint(nil), endpoints...)
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

// List returns agents, optionally only online.
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

// SnapshotAgents returns a copy of all agents (for netmap building).
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

func dnsName(name, suffix string) string {
	return name + "." + suffix
}
