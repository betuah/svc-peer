package hub

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigTLSBothOrNeither(t *testing.T) {
	dir := t.TempDir()
	base := `
listen_addr: ":8080"
hub_id: "hub-main"
center_bootstrap: "boot"
relay_secret: "relay"
overlay_cidr: "10.10.0.0/16"
`
	okPath := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(okPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(okPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSEnabled() {
		t.Fatal("expected TLS disabled when paths empty")
	}

	certOnly := base + "tls_cert_file: /tmp/cert.pem\n"
	certPath := filepath.Join(dir, "cert-only.yaml")
	if err := os.WriteFile(certPath, []byte(certOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(certPath); err == nil {
		t.Fatal("expected error when only tls_cert_file is set")
	}

	both := base + "tls_cert_file: /tmp/cert.pem\ntls_key_file: /tmp/key.pem\n"
	bothPath := filepath.Join(dir, "both.yaml")
	if err := os.WriteFile(bothPath, []byte(both), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(bothPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLSEnabled() {
		t.Fatal("expected TLS enabled when both paths set")
	}
	if cfg.TLSCertFile != "/tmp/cert.pem" || cfg.TLSKeyFile != "/tmp/key.pem" {
		t.Fatalf("paths: cert=%q key=%q", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

func TestConfigValidateTLSMismatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSCertFile = "cert.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for cert without key")
	}
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = "key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for key without cert")
	}
}

func TestConfigValidateLog(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogLevel = "trace"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for bad log_level")
	}
	cfg.LogLevel = "info"
	cfg.LogFormat = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for bad log_format")
	}
}
