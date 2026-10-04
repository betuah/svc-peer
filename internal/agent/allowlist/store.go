// Package allowlist persists center-authored edge join tokens on the agent host.
// The center agent is the source of truth; the hub holds a synced cache.
package allowlist

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/google/uuid"
)

const (
	fileName = "allowlist.json"

	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var (
	ErrNotFound      = errors.New("allowlist entry not found")
	ErrAlreadyExists = errors.New("allowlist entry already exists")
	ErrRevoked       = errors.New("allowlist entry revoked")
)

// Seed is a config-file edge token merged into the durable store on center start.
type Seed struct {
	ID    string
	Token string
	Label string
	Tags  []string
}

// Entry is one edge join token held by the center.
type Entry struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	Label     string     `json:"label,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type fileState struct {
	Entries []Entry `json:"entries"`
}

// Store is a durable, center-local allowlist.
type Store struct {
	path string
	mu   sync.RWMutex
	byID map[string]*Entry
}

// Open loads or creates allowlist.json under stateDir (alongside agent_id).
func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("state_dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	s := &Store{
		path: filepath.Join(stateDir, fileName),
		byID: make(map[string]*Entry),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the on-disk JSON path.
func (s *Store) Path() string { return s.path }

// SeedFromConfig merges YAML edge_tokens into the store.
// Missing ids are inserted. Active ids are updated from the seed.
// Revoked ids are left revoked (config does not resurrect them).
func (s *Store) SeedFromConfig(seeds []Seed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, seed := range seeds {
		if seed.Token == "" {
			return fmt.Errorf("edge token seed %q: empty token", seed.ID)
		}
		id := seed.ID
		if id == "" {
			id = uuid.NewString()
		}
		if existing, ok := s.byID[id]; ok {
			if existing.Status == StatusRevoked {
				continue
			}
			existing.Token = seed.Token
			existing.Label = seed.Label
			existing.Tags = append([]string(nil), seed.Tags...)
			changed = true
			continue
		}
		now := time.Now().UTC()
		s.byID[id] = &Entry{
			ID:        id,
			Token:     seed.Token,
			Label:     seed.Label,
			Tags:      append([]string(nil), seed.Tags...),
			Status:    StatusActive,
			CreatedAt: now,
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return s.persistLocked()
}

// List returns copies of all entries sorted by id.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, copyEntry(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a copy of one entry.
func (s *Store) Get(id string) (Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return copyEntry(e), nil
}

// Add creates an active entry. Empty id/token are generated.
func (s *Store) Add(id, token, label string, tags []string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		id = uuid.NewString()
	}
	if _, exists := s.byID[id]; exists {
		return Entry{}, ErrAlreadyExists
	}
	if token == "" {
		var err error
		token, err = randomToken()
		if err != nil {
			return Entry{}, err
		}
	}
	for _, e := range s.byID {
		if e.Token == token && e.Status == StatusActive {
			return Entry{}, fmt.Errorf("token secret already used by id %q", e.ID)
		}
	}
	now := time.Now().UTC()
	rec := &Entry{
		ID:        id,
		Token:     token,
		Label:     label,
		Tags:      append([]string(nil), tags...),
		Status:    StatusActive,
		CreatedAt: now,
	}
	s.byID[id] = rec
	if err := s.persistLocked(); err != nil {
		delete(s.byID, id)
		return Entry{}, err
	}
	return copyEntry(rec), nil
}

// Revoke marks an entry revoked. Idempotent if already revoked.
func (s *Store) Revoke(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	if e.Status != StatusRevoked {
		now := time.Now().UTC()
		e.Status = StatusRevoked
		e.RevokedAt = &now
		if err := s.persistLocked(); err != nil {
			return Entry{}, err
		}
	}
	return copyEntry(e), nil
}

// ActiveTokens returns hub sync payloads for active entries.
func (s *Store) ActiveTokens() []protocol.AllowlistToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]protocol.AllowlistToken, 0, len(s.byID))
	for _, e := range s.byID {
		if e.Status != StatusActive {
			continue
		}
		out = append(out, protocol.AllowlistToken{
			ID:    e.ID,
			Token: e.Token,
			Label: e.Label,
			Tags:  append([]string(nil), e.Tags...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RevokedIDs returns ids that should be revoked on the hub cache.
func (s *Store) RevokedIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0)
	for _, e := range s.byID {
		if e.Status == StatusRevoked {
			out = append(out, e.ID)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read allowlist: %w", err)
	}
	var st fileState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse allowlist: %w", err)
	}
	for i := range st.Entries {
		e := st.Entries[i]
		if e.ID == "" || e.Token == "" {
			return fmt.Errorf("allowlist entry missing id or token")
		}
		if e.Status == "" {
			e.Status = StatusActive
		}
		switch e.Status {
		case StatusActive, StatusRevoked:
		default:
			return fmt.Errorf("allowlist entry %q: invalid status %q", e.ID, e.Status)
		}
		cp := e
		cp.Tags = append([]string(nil), e.Tags...)
		if e.RevokedAt != nil {
			t := e.RevokedAt.UTC()
			cp.RevokedAt = &t
		}
		cp.CreatedAt = e.CreatedAt.UTC()
		s.byID[cp.ID] = &cp
	}
	return nil
}

func (s *Store) persistLocked() error {
	entries := make([]Entry, 0, len(s.byID))
	for _, e := range s.byID {
		entries = append(entries, copyEntry(e))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	data, err := json.MarshalIndent(fileState{Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write allowlist temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("persist allowlist: %w", err)
	}
	return nil
}

func copyEntry(e *Entry) Entry {
	cp := *e
	cp.Tags = append([]string(nil), e.Tags...)
	if e.RevokedAt != nil {
		t := e.RevokedAt.UTC()
		cp.RevokedAt = &t
	}
	return cp
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "spt_" + hex.EncodeToString(b), nil
}
