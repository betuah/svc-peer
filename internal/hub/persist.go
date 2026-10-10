package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateFileVersion = 1

// stateFile is the on-disk JSON snapshot for durable hub membership + allowlist cache.
// Online presence, last-seen, and endpoints are intentionally omitted (ephemeral).
type stateFile struct {
	Version    int              `json:"version"`
	HubID      string           `json:"hub_id"`
	SavedAt    time.Time        `json:"saved_at"`
	Agents     []persistedAgent `json:"agents"`
	EdgeTokens []persistedToken `json:"edge_tokens"`
}

type persistedAgent struct {
	ID           string   `json:"agent_id"`
	HubID        string   `json:"hub_id"`
	Role         string   `json:"role"`
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	OverlayIP    string   `json:"overlay_ip"`
	DNSName      string   `json:"dns_name"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	WGBackend    string   `json:"wg_backend,omitempty"`
	TokenID      string   `json:"token_id,omitempty"`
}

type persistedToken struct {
	ID        string    `json:"id"`
	HubID     string    `json:"hub_id"`
	Role      string    `json:"role"`
	Label     string    `json:"label,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Hash      string    `json:"hash"`
	AgentID   string    `json:"agent_id,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// FileStore loads and saves hub durable state as a single JSON file.
type FileStore struct {
	path string
}

// NewFileStore returns a store writing to path. Empty path disables persistence.
func NewFileStore(path string) *FileStore {
	if path == "" {
		return nil
	}
	return &FileStore{path: path}
}

// Path returns the configured state file path.
func (s *FileStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load reads the state file. Missing file returns (nil, nil).
func (s *FileStore) Load() (*stateFile, error) {
	if s == nil || s.path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read hub state: %w", err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse hub state: %w", err)
	}
	if st.Version != 0 && st.Version != stateFileVersion {
		return nil, fmt.Errorf("unsupported hub state version %d", st.Version)
	}
	return &st, nil
}

// Save writes st atomically (temp file + rename).
func (s *FileStore) Save(st *stateFile) error {
	if s == nil || s.path == "" {
		return nil
	}
	if st == nil {
		return fmt.Errorf("nil state")
	}
	st.Version = stateFileVersion
	st.SavedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode hub state: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create hub state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "hub-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create hub state temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write hub state temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod hub state temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close hub state temp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename hub state: %w", err)
	}
	cleanup = false
	return nil
}
