package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePersistsAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	id1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" {
		t.Fatal("empty id")
	}
	id2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("agent id changed: %s → %s", id1, id2)
	}
	raw, err := os.ReadFile(filepath.Join(dir, agentIDFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != id1+"\n" {
		t.Fatalf("file contents: %q", raw)
	}
}

func TestLoadOrCreateRequiresStateDir(t *testing.T) {
	if _, err := LoadOrCreate(""); err == nil {
		t.Fatal("expected error")
	}
}
