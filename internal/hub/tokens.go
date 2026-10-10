package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

// Token roles on the thin hub.
const (
	RoleManagement = "management"
	RoleEdgeToken  = "edge" // join/agent token for edges (synced from center)
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token revoked")
	ErrTokenInvalid  = errors.New("invalid token")
	ErrWrongHub      = errors.New("token hub_id mismatch")
	ErrWrongRole     = errors.New("token role not allowed")
)

// TokenRecord is a durable credential scoped to a hub_id.
// For edge tokens, AgentID is empty until first successful edge register.
type TokenRecord struct {
	ID        string
	HubID     string
	Role      string // management | edge
	Label     string
	Tags      []string
	Hash      string // sha256 hex of raw token
	AgentID   string // bound on first successful edge register
	Revoked   bool
	CreatedAt time.Time
}

// TokenStore is an in-memory token/allowlist store for one hub_id.
type TokenStore struct {
	hubID  string
	mu     sync.RWMutex
	byID   map[string]*TokenRecord
	byHash map[string]*TokenRecord
}

// NewTokenStore creates an empty store scoped to hubID.
func NewTokenStore(hubID string) *TokenStore {
	return &TokenStore{
		hubID:  hubID,
		byID:   make(map[string]*TokenRecord),
		byHash: make(map[string]*TokenRecord),
	}
}

// HubID returns the store's hub scope.
func (s *TokenStore) HubID() string { return s.hubID }

// EdgeAllowlistCount returns the number of non-revoked edge join tokens.
func (s *TokenStore) EdgeAllowlistCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, rec := range s.byID {
		if rec.Role == RoleEdgeToken && !rec.Revoked {
			n++
		}
	}
	return n
}

// SeedManagement loads the bootstrap / management-token seed (ops/break-glass).
func (s *TokenStore) SeedManagement(id, raw string) error {
	if raw == "" {
		return fmt.Errorf("management token seed: empty token")
	}
	if id == "" {
		id = "mgmt-bootstrap"
	}
	return s.seed(id, raw, RoleManagement, "management", nil)
}

// UpsertEdgeAllowlist inserts or updates edge join tokens from a center sync.
// Raw tokens are hashed; never stored plaintext.
func (s *TokenStore) UpsertEdgeAllowlist(items []protocol.AllowlistToken) ([]*TokenRecord, error) {
	out := make([]*TokenRecord, 0, len(items))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range items {
		if it.Token == "" {
			return nil, fmt.Errorf("allowlist token empty")
		}
		id := it.ID
		if id == "" {
			id = uuid.NewString()
		}
		hash := hashToken(it.Token)
		if existing, ok := s.byID[id]; ok {
			if existing.Role != RoleEdgeToken {
				return nil, fmt.Errorf("token id %q is not an edge join token", id)
			}
			if other, ok := s.byHash[hash]; ok && other.ID != id {
				return nil, fmt.Errorf("allowlist token collision for id %q", id)
			}
			delete(s.byHash, existing.Hash)
			existing.Hash = hash
			existing.Label = it.Label
			existing.Tags = append([]string(nil), it.Tags...)
			existing.Revoked = false
			s.byHash[hash] = existing
			cp := *existing
			out = append(out, &cp)
			continue
		}
		if _, exists := s.byHash[hash]; exists {
			return nil, fmt.Errorf("allowlist token collision for id %q", id)
		}
		rec := &TokenRecord{
			ID:        id,
			HubID:     s.hubID,
			Role:      RoleEdgeToken,
			Label:     it.Label,
			Tags:      append([]string(nil), it.Tags...),
			Hash:      hash,
			CreatedAt: time.Now().UTC(),
		}
		s.byID[id] = rec
		s.byHash[hash] = rec
		cp := *rec
		out = append(out, &cp)
	}
	return out, nil
}

func (s *TokenStore) seed(id, raw, role, label string, tags []string) error {
	hash := hashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[id]; exists {
		return fmt.Errorf("pre-seed token id %q already exists", id)
	}
	if _, exists := s.byHash[hash]; exists {
		return fmt.Errorf("pre-seed token collision for id %q", id)
	}
	rec := &TokenRecord{
		ID:        id,
		HubID:     s.hubID,
		Role:      role,
		Label:     label,
		Tags:      append([]string(nil), tags...),
		Hash:      hash,
		CreatedAt: time.Now().UTC(),
	}
	s.byID[id] = rec
	s.byHash[hash] = rec
	return nil
}

// MintEdge creates a new edge join token (break-glass / management only).
func (s *TokenStore) MintEdge(hubID, label string, tags []string) (*TokenRecord, string, error) {
	if hubID != s.hubID {
		return nil, "", ErrWrongHub
	}
	raw, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	hash := hashToken(raw)
	rec := &TokenRecord{
		ID:        uuid.NewString(),
		HubID:     s.hubID,
		Role:      RoleEdgeToken,
		Label:     label,
		Tags:      append([]string(nil), tags...),
		Hash:      hash,
		CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[rec.ID] = rec
	s.byHash[hash] = rec
	return rec, raw, nil
}

// Lookup validates a raw token and returns the record.
func (s *TokenStore) Lookup(raw string) (*TokenRecord, error) {
	if raw == "" {
		return nil, ErrTokenInvalid
	}
	hash := hashToken(raw)
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return nil, ErrTokenNotFound
	}
	if rec.Revoked {
		return nil, ErrTokenRevoked
	}
	if rec.HubID != s.hubID {
		return nil, ErrWrongHub
	}
	cp := *rec
	return &cp, nil
}

// BindAgentID binds an Agent ID on first successful edge register.
func (s *TokenStore) BindAgentID(tokenID, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[tokenID]
	if !ok {
		return ErrTokenNotFound
	}
	if rec.Revoked {
		return ErrTokenRevoked
	}
	if rec.Role != RoleEdgeToken {
		return ErrWrongRole
	}
	if rec.AgentID != "" && rec.AgentID != agentID {
		return fmt.Errorf("token already bound to different agent")
	}
	rec.AgentID = agentID
	return nil
}

// Revoke marks a token revoked.
func (s *TokenStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return ErrTokenNotFound
	}
	rec.Revoked = true
	return nil
}

// Rotate issues a new raw secret for the same token ID and Agent ID binding.
func (s *TokenStore) Rotate(id string) (*TokenRecord, string, error) {
	raw, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	newHash := hashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[id]
	if !ok {
		return nil, "", ErrTokenNotFound
	}
	if rec.Revoked {
		return nil, "", ErrTokenRevoked
	}
	if rec.Role != RoleEdgeToken {
		return nil, "", ErrWrongRole
	}
	delete(s.byHash, rec.Hash)
	rec.Hash = newHash
	s.byHash[newHash] = rec
	cp := *rec
	return &cp, raw, nil
}

// Get returns a token record by ID.
func (s *TokenStore) Get(id string) (*TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byID[id]
	if !ok {
		return nil, ErrTokenNotFound
	}
	cp := *rec
	return &cp, nil
}

// SnapshotEdge returns copies of edge join-token records for durable cache.
// Management tokens are config-seeded and not included.
func (s *TokenStore) SnapshotEdge() []TokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenRecord, 0, len(s.byID))
	for _, rec := range s.byID {
		if rec.Role != RoleEdgeToken {
			continue
		}
		cp := *rec
		cp.Tags = append([]string(nil), rec.Tags...)
		out = append(out, cp)
	}
	return out
}

// RestoreEdge loads edge join tokens from durable storage (hashes only; no plaintext).
// Skips records that collide with an already-seeded id/hash (e.g. management seed).
func (s *TokenStore) RestoreEdge(recs []TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range recs {
		if in.ID == "" || in.Hash == "" {
			return fmt.Errorf("restore edge token: id and hash required")
		}
		if in.Role != "" && in.Role != RoleEdgeToken {
			return fmt.Errorf("restore edge token %q: unexpected role %q", in.ID, in.Role)
		}
		if existing, ok := s.byID[in.ID]; ok {
			if existing.Role != RoleEdgeToken {
				continue // keep config-seeded management token
			}
			return fmt.Errorf("restore edge token: duplicate id %q", in.ID)
		}
		if _, exists := s.byHash[in.Hash]; exists {
			return fmt.Errorf("restore edge token: hash collision for id %q", in.ID)
		}
		rec := &TokenRecord{
			ID:        in.ID,
			HubID:     s.hubID,
			Role:      RoleEdgeToken,
			Label:     in.Label,
			Tags:      append([]string(nil), in.Tags...),
			Hash:      in.Hash,
			AgentID:   in.AgentID,
			Revoked:   in.Revoked,
			CreatedAt: in.CreatedAt,
		}
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = time.Now().UTC()
		}
		s.byID[rec.ID] = rec
		s.byHash[rec.Hash] = rec
	}
	return nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "spt_" + hex.EncodeToString(b), nil
}
