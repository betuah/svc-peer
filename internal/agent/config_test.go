// Unit tests: agent config defaults and wg_backend validation.
package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigKernelFirstAuto(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WGBackend != "auto" {
		t.Fatalf("default wg_backend=%q want auto (kernel-first)", cfg.WGBackend)
	}
	if cfg.LocalAPIListen != "127.0.0.1:9100" {
		t.Fatalf("default local_api_listen=%q want 127.0.0.1:9100", cfg.LocalAPIListen)
	}
}

func TestLoadConfigRejectsUnknownBackend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	content := []byte("hub_url: http://127.0.0.1:8080\nstate_dir: ./s\ntoken: t\nname: n\nwg_backend: weird\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for unknown wg_backend")
	}
}

func TestLoadConfigNormalizesEmptyBackendToAuto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	content := []byte("hub_url: http://127.0.0.1:8080\nstate_dir: ./s\ntoken: t\nname: n\nwg_backend: \"\"\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WGBackend != "auto" {
		t.Fatalf("got %q", cfg.WGBackend)
	}
}

func TestLoadConfigCenterRequiresBootstrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	content := []byte("hub_url: http://127.0.0.1:8080\nstate_dir: ./s\nrole: center\nname: center\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error without center_bootstrap")
	}
}

func TestLoadConfigHubURLScheme(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	edgeBase := "\nstate_dir: ./s\ntoken: t\nname: n\n"

	if _, err := LoadConfig(write("bad.yaml", "hub_url: ftp://127.0.0.1:8080"+edgeBase)); err == nil {
		t.Fatal("expected error for non-http scheme")
	}
	cfg, err := LoadConfig(write("https.yaml", "hub_url: https://hub.example:8443"+edgeBase))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HubURL != "https://hub.example:8443" {
		t.Fatalf("hub_url=%q", cfg.HubURL)
	}
	if cfg.HubTLSInsecureSkipVerify {
		t.Fatal("hub_tls_insecure_skip_verify must default false")
	}
	cfg, err = LoadConfig(write("insecure.yaml", "hub_url: https://hub.example:8443\nhub_tls_insecure_skip_verify: true"+edgeBase))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HubTLSInsecureSkipVerify {
		t.Fatal("expected hub_tls_insecure_skip_verify true")
	}
}
