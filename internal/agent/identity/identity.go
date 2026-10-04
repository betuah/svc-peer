// Package identity manages the locally generated Agent ID persisted on disk.
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const agentIDFile = "agent_id"

// LoadOrCreate returns the persisted Agent ID, generating and saving one on first run.
func LoadOrCreate(stateDir string) (string, error) {
	if stateDir == "" {
		return "", fmt.Errorf("state_dir is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(stateDir, agentIDFile)
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id == "" {
			return "", fmt.Errorf("empty agent_id in %s", path)
		}
		if _, err := uuid.Parse(id); err != nil {
			return "", fmt.Errorf("invalid agent_id in %s: %w", path, err)
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("read agent_id: %w", err)
	}
	id := uuid.NewString()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist agent_id: %w", err)
	}
	return id, nil
}
