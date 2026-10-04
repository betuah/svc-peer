package agent

import (
	"fmt"
	"os"

	"github.com/betuah/svc-peer/internal/protocol"
	"gopkg.in/yaml.v3"
)

// EdgeTokenSeed is an edge join token held by the center and synced to the hub allowlist.
type EdgeTokenSeed struct {
	ID    string   `yaml:"id"`
	Token string   `yaml:"token"`
	Label string   `yaml:"label"`
	Tags  []string `yaml:"tags"`
}

// Config is the agent configuration file.
type Config struct {
	HubURL string `yaml:"hub_url"`
	HubID  string `yaml:"hub_id"`
	// Role is center | edge.
	Role string `yaml:"role"`
	// CenterBootstrap is required when role=center (shared with hub center_bootstrap).
	CenterBootstrap string `yaml:"center_bootstrap"`
	// Token is the edge join token when role=edge (created/configured on center).
	Token string `yaml:"token"`
	// EdgeTokens are center-held join tokens synced to the hub allowlist (center role only).
	EdgeTokens []EdgeTokenSeed `yaml:"edge_tokens"`
	// StateDir holds the persisted local agent_id (and optionally other state).
	StateDir string `yaml:"state_dir"`

	Name           string   `yaml:"name"`
	WGBackend      string   `yaml:"wg_backend"`
	WGInterface    string   `yaml:"wg_interface"`
	WGListenPort   int      `yaml:"wg_listen_port"`
	HeartbeatSec   int      `yaml:"heartbeat_sec"`
	Tags           []string `yaml:"tags"`
	Capabilities   []string `yaml:"capabilities"`
	PrivateKeyPath string   `yaml:"private_key_path"`
	DirectWaitSec  int      `yaml:"direct_wait_sec"`
	// LocalAPIListen is the bind address for the agent-local HTTP API (loopback by default).
	// Empty disables the local API.
	LocalAPIListen string `yaml:"local_api_listen"`
}

// DefaultConfig returns agent defaults.
func DefaultConfig() Config {
	return Config{
		HubURL:         "http://127.0.0.1:8080",
		HubID:          "hub-main",
		Role:           protocol.RoleEdge,
		StateDir:       "./state",
		WGBackend:      "auto",
		WGInterface:    "sp0",
		WGListenPort:   51820,
		HeartbeatSec:   15,
		DirectWaitSec:  8,
		LocalAPIListen: "127.0.0.1:9100",
	}
}

// AuthCredential returns the Bearer credential for this agent role.
func (c Config) AuthCredential() string {
	if c.Role == protocol.RoleCenter {
		return c.CenterBootstrap
	}
	return c.Token
}

// LoadConfig reads agent YAML config.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read agent config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse agent config: %w", err)
	}
	if cfg.HubURL == "" {
		return cfg, fmt.Errorf("hub_url is required")
	}
	if cfg.Name == "" {
		return cfg, fmt.Errorf("name is required")
	}
	if cfg.StateDir == "" {
		return cfg, fmt.Errorf("state_dir is required (persists local agent_id)")
	}
	switch cfg.Role {
	case "", protocol.RoleEdge:
		cfg.Role = protocol.RoleEdge
		if cfg.Token == "" {
			return cfg, fmt.Errorf("token is required for edge agents (join token from center)")
		}
		if cfg.CenterBootstrap != "" {
			return cfg, fmt.Errorf("center_bootstrap must not be set on edge agents")
		}
	case protocol.RoleCenter:
		if cfg.CenterBootstrap == "" {
			return cfg, fmt.Errorf("center_bootstrap is required for center agents")
		}
		if cfg.Token != "" {
			return cfg, fmt.Errorf("token must not be set on center agents (use center_bootstrap)")
		}
	default:
		return cfg, fmt.Errorf("role must be center|edge (got %q)", cfg.Role)
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 15
	}
	if cfg.DirectWaitSec <= 0 {
		cfg.DirectWaitSec = 8
	}
	switch cfg.WGBackend {
	case "", "auto", "kernel", "userspace":
		if cfg.WGBackend == "" {
			cfg.WGBackend = "auto"
		}
	default:
		return cfg, fmt.Errorf("wg_backend must be auto|kernel|userspace (got %q)", cfg.WGBackend)
	}
	return cfg, nil
}
