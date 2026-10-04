// Package grants persists center-authored A2A peer grants on the agent host.
// The center agent is the source of truth; the hub applies grants into the netmap.
package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	fileName = "grants.json"

	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var (
	ErrNotFound      = errors.New("grant not found")
	ErrAlreadyExists = errors.New("grant already exists")
	ErrInvalid       = errors.New("invalid grant")
)

// Entry is one center-authored A2A grant.
type Entry struct {
	ID        string     `json:"id"`
	AgentAID  string     `json:"agent_a_id"`
	AgentBID  string     `json:"agent_b_id"`
	Status    string     `json:"status"` // active | revoked
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type fileState struct {
	Entries []Entry `json:"entries"`
}

// Store is a durable, center-local grant list.
type Store struct {
	path   string
	mu     sync.RWMutex
	byID   map[string]*Entry
	byPair map[string]string // canonical "a|b" → id (active only)
}

// Open loads or creates grants.json under stateDir (alongside agent_id / allowlist).
func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("state_dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	s := &Store{
		path:   filepath.Join(stateDir, fileName),
		byID:   make(map[string]*Entry),
		byPair: make(map[string]string),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the on-disk JSON path.
func (s *Store) Path() string { return s.path }

func pairKey(a, b string) string {
	if a <= b {
		return a + "|" + b
	}
	return b + "|" + a
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

// Add creates an active grant between two agent IDs. Empty id is generated.
func (s *Store) Add(id, agentA, agentB string) (Entry, error) {
	if agentA == "" || agentB == "" || agentA == agentB {
		return Entry{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		id = uuid.NewString()
	}
	if _, exists := s.byID[id]; exists {
		return Entry{}, ErrAlreadyExists
	}
	key := pairKey(agentA, agentB)
	if existingID, ok := s.byPair[key]; ok {
		return Entry{}, fmt.Errorf("%w: pair already granted as %s", ErrAlreadyExists, existingID)
	}
	now := time.Now().UTC()
	rec := &Entry{
		ID:        id,
		AgentAID:  agentA,
		AgentBID:  agentB,
		Status:    StatusActive,
		CreatedAt: now,
	}
	s.byID[id] = rec
	s.byPair[key] = id
	if err := s.persistLocked(); err != nil {
		delete(s.byID, id)
		delete(s.byPair, key)
		return Entry{}, err
	}
	return copyEntry(rec), nil
}

// Revoke marks a grant revoked. Idempotent if already revoked.
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
		delete(s.byPair, pairKey(e.AgentAID, e.AgentBID))
		if err := s.persistLocked(); err != nil {
			return Entry{}, err
		}
	}
	return copyEntry(e), nil
}

// Active returns active grants sorted by id (hub sync payloads).
func (s *Store) Active() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.byID))
	for _, e := range s.byID {
		if e.Status != StatusActive {
			continue
		}
		out = append(out, copyEntry(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RevokedIDs returns ids that should be revoked on the hub.
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
		return fmt.Errorf("read grants: %w", err)
	}
	var st fileState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse grants: %w", err)
	}
	for i := range st.Entries {
		e := st.Entries[i]
		if e.ID == "" || e.AgentAID == "" || e.AgentBID == "" {
			return fmt.Errorf("grant entry missing id or agent ids")
		}
		if e.AgentAID == e.AgentBID {
			return fmt.Errorf("grant %q: agent ids must differ", e.ID)
		}
		if e.Status == "" {
			e.Status = StatusActive
		}
		switch e.Status {
		case StatusActive, StatusRevoked:
		default:
			return fmt.Errorf("grant %q: invalid status %q", e.ID, e.Status)
		}
		cp := e
		cp.CreatedAt = e.CreatedAt.UTC()
		if e.RevokedAt != nil {
			t := e.RevokedAt.UTC()
			cp.RevokedAt = &t
		}
		if _, exists := s.byID[cp.ID]; exists {
			return fmt.Errorf("duplicate grant id %q", cp.ID)
		}
		s.byID[cp.ID] = &cp
		if cp.Status == StatusActive {
			key := pairKey(cp.AgentAID, cp.AgentBID)
			if other, ok := s.byPair[key]; ok {
				return fmt.Errorf("duplicate active pair for %q and %q", other, cp.ID)
			}
			s.byPair[key] = cp.ID
		}
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
		return fmt.Errorf("write grants temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("persist grants: %w", err)
	}
	return nil
}

func copyEntry(e *Entry) Entry {
	cp := *e
	if e.RevokedAt != nil {
		t := e.RevokedAt.UTC()
		cp.RevokedAt = &t
	}
	return cp
}
