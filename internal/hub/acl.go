package hub

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrGrantNotFound = errors.New("grant not found")
	ErrGrantExists   = errors.New("grant already exists")
	ErrGrantInvalid  = errors.New("invalid grant")
)

// Grant is an explicit agent↔agent direct-WG allowance on one hub.
type Grant struct {
	ID        string
	AgentA    string
	AgentB    string
	CreatedAt time.Time
}

// GrantStore holds A2A grants. Default policy is deny (no entries).
type GrantStore struct {
	mu     sync.RWMutex
	byID   map[string]*Grant
	byPair map[string]string // canonical "a|b" → grant id
}

// NewGrantStore creates an empty grant store (A2A drop by default).
func NewGrantStore() *GrantStore {
	return &GrantStore{
		byID:   make(map[string]*Grant),
		byPair: make(map[string]string),
	}
}

func pairKey(a, b string) string {
	if a <= b {
		return a + "|" + b
	}
	return b + "|" + a
}

// Grant adds a reciprocal A2A allowance. Hub is not in the dataplane path.
func (s *GrantStore) Grant(agentA, agentB string) (*Grant, error) {
	g, _, err := s.GrantWithID("", agentA, agentB)
	return g, err
}

// GrantWithID adds a grant with an optional center-supplied id.
// Same id+pair (or same pair when id is empty) is idempotent: created=false.
func (s *GrantStore) GrantWithID(id, agentA, agentB string) (*Grant, bool, error) {
	if agentA == "" || agentB == "" || agentA == agentB {
		return nil, false, ErrGrantInvalid
	}
	key := pairKey(agentA, agentB)
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		if existing, ok := s.byID[id]; ok {
			if pairKey(existing.AgentA, existing.AgentB) == key {
				cp := *existing
				return &cp, false, nil
			}
			return nil, false, ErrGrantExists
		}
	}
	if _, exists := s.byPair[key]; exists {
		return nil, false, ErrGrantExists
	}
	if id == "" {
		id = uuid.NewString()
	}
	g := &Grant{
		ID:        id,
		AgentA:    agentA,
		AgentB:    agentB,
		CreatedAt: time.Now().UTC(),
	}
	s.byID[g.ID] = g
	s.byPair[key] = g.ID
	cp := *g
	return &cp, true, nil
}

// Revoke removes a grant by ID.
func (s *GrantStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[id]
	if !ok {
		return ErrGrantNotFound
	}
	delete(s.byID, id)
	delete(s.byPair, pairKey(g.AgentA, g.AgentB))
	return nil
}

// Allowed reports whether A↔B has an explicit grant.
func (s *GrantStore) Allowed(agentA, agentB string) bool {
	if agentA == "" || agentB == "" || agentA == agentB {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byPair[pairKey(agentA, agentB)]
	return ok
}

// PeersOf returns agent IDs that have a direct grant with agentID.
func (s *GrantStore) PeersOf(agentID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0)
	for _, g := range s.byID {
		switch agentID {
		case g.AgentA:
			out = append(out, g.AgentB)
		case g.AgentB:
			out = append(out, g.AgentA)
		}
	}
	return out
}

// Get returns a grant by ID.
func (s *GrantStore) Get(id string) (*Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.byID[id]
	if !ok {
		return nil, ErrGrantNotFound
	}
	cp := *g
	return &cp, nil
}

// List returns all grants.
func (s *GrantStore) List() []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0, len(s.byID))
	for _, g := range s.byID {
		out = append(out, *g)
	}
	return out
}

// Count returns the number of active grants.
func (s *GrantStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// String aids debugging.
func (g Grant) String() string {
	return fmt.Sprintf("grant(%s:%s↔%s)", g.ID, g.AgentA, g.AgentB)
}
