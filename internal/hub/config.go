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
	RelaySecret string   `yaml:"relay_secret"`
	OverlayCIDR string   `yaml:"overlay_cidr"`
	DNSSuffix   string   `yaml:"dns_suffix"`
	STUNURLs    []string `yaml:"stun_urls"`
	RelayURLs   []string `yaml:"relay_urls"`
	// HeartbeatTimeout is how long without heartbeat before an agent is offline.
	HeartbeatTimeoutSec int `yaml:"heartbeat_timeout_sec"`
	// StatePath is the JSON file used to persist allowlist cache + registered agents
	// across hub restarts. Empty disables durable state (in-memory only).
	// Online presence is never persisted; center re-syncs allowlist on connect.
	StatePath string `yaml:"state_path"`
	// TLSCertFile and TLSKeyFile enable HTTPS for the hub REST API and WSS for
	// control WebSocket upgrades. Leave both empty for plain HTTP (local/dev).
	// Setting only one is an error.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// LogLevel is info (default) or debug.
	LogLevel string `yaml:"log_level"`
	// LogFormat is text (default, readable on servers) or json (for collectors).
	LogFormat string `yaml:"log_format"`
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
		LogLevel:            "info",
		LogFormat:           "text",
	}
}

// TLSEnabled reports whether both TLS certificate and key paths are configured.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
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
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks required fields and TLS path consistency.
func (c *Config) Validate() error {
	if c.HubID == "" {
		return fmt.Errorf("hub_id is required")
	}
	if c.CenterBootstrap == "" {
		return fmt.Errorf("center_bootstrap is required (shared with center agent config)")
	}
	if c.RelaySecret == "" {
		return fmt.Errorf("relay_secret is required (HMAC for relay tickets; not an auth token)")
	}
	if c.OverlayCIDR == "" {
		return fmt.Errorf("overlay_cidr is required")
	}
	if c.HeartbeatTimeoutSec <= 0 {
		c.HeartbeatTimeoutSec = 45
	}
	if c.DNSSuffix == "" {
		c.DNSSuffix = "peer.local"
	}
	certSet := c.TLSCertFile != ""
	keySet := c.TLSKeyFile != ""
	if certSet != keySet {
		return fmt.Errorf("tls_cert_file and tls_key_file must both be set or both empty")
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "text"
	}
	switch c.LogLevel {
	case "info", "debug":
	default:
		return fmt.Errorf("log_level must be info or debug (got %q)", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("log_format must be text or json (got %q)", c.LogFormat)
	}
	return nil
}
