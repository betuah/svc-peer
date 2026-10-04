package hub

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the thin hub (NAT bridge / signaling) configuration.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	HubID      string `yaml:"hub_id"`
	// CenterBootstrap is shared with the center agent config. Used only for the center's
	// first register (claims sole center for hub_id). Not for edges; not day-to-day mint.
	CenterBootstrap string `yaml:"center_bootstrap"`
	// ManagementTokenSeed bootstraps ops/break-glass management token (optional).
	ManagementTokenSeed string `yaml:"management_token_seed"`
	// RelaySecret is the HMAC key for relay tickets (shared with the relay process).
	RelaySecret string `yaml:"relay_secret"`
	OverlayCIDR string `yaml:"overlay_cidr"`
	DNSSuffix   string `yaml:"dns_suffix"`
	STUNURLs    []string `yaml:"stun_urls"`
	RelayURLs   []string `yaml:"relay_urls"`
	// HeartbeatTimeout is how long without heartbeat before an agent is offline.
	HeartbeatTimeoutSec int `yaml:"heartbeat_timeout_sec"`
}

// DefaultConfig returns sensible MVP defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          ":8080",
		HubID:               "hub-main",
		CenterBootstrap:     "change-me-center-bootstrap",
		ManagementTokenSeed: "change-me-management-token",
		RelaySecret:         "change-me-relay-secret",
		OverlayCIDR:         "10.10.0.0/16",
		DNSSuffix:           "peer.local",
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
	if cfg.CenterBootstrap == "" {
		return cfg, fmt.Errorf("center_bootstrap is required (shared with center agent config)")
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
