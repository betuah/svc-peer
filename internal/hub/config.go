package hub

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the hub configuration file.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	HubID      string `yaml:"hub_id"`
	// ManagementTokenSeed bootstraps the first management token (not a parallel hub_secret auth system).
	ManagementTokenSeed string `yaml:"management_token_seed"`
	// RelaySecret is the HMAC key for relay tickets (shared with the relay process). Separate from auth tokens.
	RelaySecret string `yaml:"relay_secret"`
	OverlayCIDR string `yaml:"overlay_cidr"`
	DNSSuffix   string `yaml:"dns_suffix"`
	// HubEndpoint is the public/host:port for the hub WireGuard peer advertised to agents.
	HubEndpoint string   `yaml:"hub_endpoint"`
	STUNURLs    []string `yaml:"stun_urls"`
	RelayURLs   []string `yaml:"relay_urls"`
	// PreSeedTokens are long-lived agent tokens loaded at startup (before first register).
	PreSeedTokens []PreSeedToken `yaml:"pre_seed_tokens"`
	// HeartbeatTimeout is how long without heartbeat before an agent is offline.
	HeartbeatTimeoutSec int `yaml:"heartbeat_timeout_sec"`
}

// PreSeedToken is a config-file provisioned agent credential.
type PreSeedToken struct {
	ID    string   `yaml:"id"`
	Token string   `yaml:"token"`
	Label string   `yaml:"label"`
	Tags  []string `yaml:"tags"`
}

// DefaultConfig returns sensible MVP defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          ":8080",
		HubID:               "hub-main",
		ManagementTokenSeed: "change-me-management-token",
		RelaySecret:         "change-me-relay-secret",
		OverlayCIDR:         "10.10.0.0/16",
		DNSSuffix:           "peer.local",
		HubEndpoint:         "127.0.0.1:51820",
		STUNURLs:            []string{"stun:stun.l.google.com:19302"},
		RelayURLs:           []string{"udp://127.0.0.1:3478", "ws://127.0.0.1:3479/relay"},
		HeartbeatTimeoutSec: 45,
	}
}

// LoadConfig reads YAML from path and merges with defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read hub config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse hub config: %w", err)
	}
	if cfg.HubID == "" {
		return cfg, fmt.Errorf("hub_id is required")
	}
	if cfg.ManagementTokenSeed == "" {
		return cfg, fmt.Errorf("management_token_seed is required (bootstrap for first management token)")
	}
	if cfg.RelaySecret == "" {
		return cfg, fmt.Errorf("relay_secret is required (HMAC for relay tickets; not an auth token)")
	}
	if cfg.OverlayCIDR == "" {
		return cfg, fmt.Errorf("overlay_cidr is required")
	}
	if cfg.HeartbeatTimeoutSec <= 0 {
		cfg.HeartbeatTimeoutSec = 45
	}
	if cfg.DNSSuffix == "" {
		cfg.DNSSuffix = "peer.local"
	}
	return cfg, nil
}
