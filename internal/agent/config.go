package agent

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the agent configuration file. Token is provisioned via hub /hub/tokens or pre-seed.
type Config struct {
	HubURL         string `yaml:"hub_url"`
	Token          string `yaml:"token"`
	Name           string `yaml:"name"`
	WGBackend      string `yaml:"wg_backend"` // auto | kernel | userspace
	WGInterface    string `yaml:"wg_interface"`
	WGListenPort   int      `yaml:"wg_listen_port"`
	HeartbeatSec   int      `yaml:"heartbeat_sec"`
	Tags           []string `yaml:"tags"`
	Capabilities   []string `yaml:"capabilities"`
	PrivateKeyPath string   `yaml:"private_key_path"` // optional; persist WG private key
	// DirectWaitSec is how long to wait for a WG handshake before requesting relay.
	DirectWaitSec int `yaml:"direct_wait_sec"`
}

// DefaultConfig returns agent defaults.
func DefaultConfig() Config {
	return Config{
		HubURL:       "http://127.0.0.1:8080",
		WGBackend:    "auto",
		WGInterface:  "sp0",
		WGListenPort: 51820,
		HeartbeatSec: 15,
		DirectWaitSec: 8,
	}
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
	if cfg.Token == "" {
		return cfg, fmt.Errorf("token is required (mint via POST /hub/tokens or hub pre_seed_tokens)")
	}
	if cfg.Name == "" {
		return cfg, fmt.Errorf("name is required")
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 15
	}
	if cfg.DirectWaitSec <= 0 {
		cfg.DirectWaitSec = 8
	}
	return cfg, nil
}
