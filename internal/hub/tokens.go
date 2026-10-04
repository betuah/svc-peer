package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token revoked")
	ErrTokenInvalid  = errors.New("invalid token")
)

// TokenRecord is a durable agent credential. AgentID is empty until first register.
type TokenRecord struct {
	ID        string
	Label     string
	Tags      []string
	Hash      string // sha256 hex of raw token
	AgentID   string // bound on first successful register
	Revoked   bool
	CreatedAt time.Time
}

// TokenStore is an in-memory token store (MVP).
type TokenStore struct {
	mu      sync.RWMutex
	byID    map[string]*TokenRecord
	byHash  map[string]*TokenRecord
}

// NewTokenStore creates an empty store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		byID:   make(map[string]*TokenRecord),
		byHash: make(map[string]*TokenRecord),
	}
}

// Seed loads a pre-seeded token from config. Raw token is hashed; never stored plaintext.
func (s *TokenStore) Seed(id, raw, label string, tags []string) error {
	if raw == "" {
		return fmt.Errorf("pre-seed token %q: empty token", id)
	}
	if id == "" {
		id = uuid.NewString()
	}
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
		Label:     label,
		Tags:      append([]string(nil), tags...),
		Hash:      hash,
		CreatedAt: time.Now().UTC(),
	}
	s.byID[id] = rec
	s.byHash[hash] = rec
	return nil
}

// Mint creates a new long-lived agent token. Agent ID is not assigned here.
func (s *TokenStore) Mint(label string, tags []string) (*TokenRecord, string, error) {
	raw, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	hash := hashToken(raw)
	rec := &TokenRecord{
		ID:        uuid.NewString(),
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
	cp := *rec
	return &cp, nil
}

// BindAgentID binds an Agent ID on first successful register. Idempotent if already bound.
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
	if rec.AgentID != "" && rec.AgentID != agentID {
		return fmt.Errorf("token already bound to different agent")
	}
	rec.AgentID = agentID
	return nil
}

// BoundAgentID returns the Agent ID bound to a token, if any.
func (s *TokenStore) BoundAgentID(tokenID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byID[tokenID]
	if !ok {
		return "", ErrTokenNotFound
	}
	return rec.AgentID, nil
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
