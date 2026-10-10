package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewTextInfoDefault(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(Config{}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hub listening", "component", "hub", "hub_id", "hub-main")
	out := buf.String()
	if !strings.Contains(out, "hub listening") {
		t.Fatalf("missing message: %q", out)
	}
	if !strings.Contains(out, "hub_id=hub-main") && !strings.Contains(out, `"hub_id"`) {
		t.Fatalf("missing hub_id field: %q", out)
	}
	// text format should not be JSON object lines
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("expected text format, got JSON-like: %q", out)
	}
}

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(Config{Format: "json", Level: "info"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("agent registered", "agent_id", "a1")
	out := buf.String()
	if !strings.Contains(out, `"msg":"agent registered"`) && !strings.Contains(out, `"agent registered"`) {
		t.Fatalf("expected JSON log: %q", out)
	}
}

func TestValidateRejectsBadLevel(t *testing.T) {
	cfg := Config{Level: "trace"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDebugSuppressedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(Config{Level: "info", Format: "text"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("noisy")
	if buf.Len() != 0 {
		t.Fatalf("debug should be suppressed: %q", buf.String())
	}
}
