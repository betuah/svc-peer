package relay

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the relay server configuration.
type Config struct {
	UDPListenAddr string `yaml:"udp_listen_addr"`
	HTTPListenAddr string `yaml:"http_listen_addr"` // WS/TLS path mount
	// HubURL is reserved for future ticket validation against the hub.
	HubURL string `yaml:"hub_url"`
}

// DefaultConfig returns relay defaults.
func DefaultConfig() Config {
	return Config{
		UDPListenAddr:  ":3478",
		HTTPListenAddr: ":3478",
		HubURL:         "http://127.0.0.1:8080",
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
	return cfg, nil
}
