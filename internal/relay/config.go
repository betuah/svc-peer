package relay

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the relay server configuration.
type Config struct {
	UDPListenAddr  string `yaml:"udp_listen_addr"`
	HTTPListenAddr string `yaml:"http_listen_addr"`
	HubURL         string `yaml:"hub_url"`
	// RelaySecret must match hub relay_secret (HMAC ticket verification). Not an auth token.
	RelaySecret string `yaml:"relay_secret"`
	// LogLevel is info (default) or debug.
	LogLevel string `yaml:"log_level"`
	// LogFormat is text (default, readable on servers) or json (for collectors).
	LogFormat string `yaml:"log_format"`
}

// DefaultConfig returns relay defaults.
func DefaultConfig() Config {
	return Config{
		UDPListenAddr:  ":3478",
		HTTPListenAddr: ":3479",
		HubURL:         "http://127.0.0.1:8080",
		RelaySecret:    "change-me-relay-secret",
		LogLevel:       "info",
		LogFormat:      "text",
	}
}

// LoadConfig reads relay YAML config.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read relay config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse relay config: %w", err)
	}
	if cfg.RelaySecret == "" {
		return cfg, fmt.Errorf("relay_secret is required")
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "text"
	}
	switch cfg.LogLevel {
	case "info", "debug":
	default:
		return cfg, fmt.Errorf("log_level must be info or debug (got %q)", cfg.LogLevel)
	}
	switch cfg.LogFormat {
	case "text", "json":
	default:
		return cfg, fmt.Errorf("log_format must be text or json (got %q)", cfg.LogFormat)
	}
	return cfg, nil
}
