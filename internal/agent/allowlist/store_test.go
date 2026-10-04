package allowlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistSeedAddRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SeedFromConfig([]Seed{{
		ID: "seed-1", Token: "spt_seed_one", Label: "cam", Tags: []string{"warehouse"},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); err != nil {
		t.Fatalf("expected allowlist.json: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := s2.List()
	if len(list) != 1 || list[0].ID != "seed-1" || list[0].Token != "spt_seed_one" {
		t.Fatalf("reload=%+v", list)
	}

	created, err := s2.Add("", "", "viewer", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Token == "" || created.Status != StatusActive {
		t.Fatalf("created=%+v", created)
	}
	if len(s2.ActiveTokens()) != 2 {
		t.Fatalf("active=%d", len(s2.ActiveTokens()))
	}

	revoked, err := s2.Revoke("seed-1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked=%+v", revoked)
	}
	if len(s2.ActiveTokens()) != 1 || s2.ActiveTokens()[0].ID != created.ID {
		t.Fatalf("active after revoke=%+v", s2.ActiveTokens())
	}
	if got := s2.RevokedIDs(); len(got) != 1 || got[0] != "seed-1" {
		t.Fatalf("revoked ids=%v", got)
	}

	// Seed must not resurrect revoked entry.
	if err := s2.SeedFromConfig([]Seed{{
		ID: "seed-1", Token: "spt_seed_one", Label: "cam",
	}}); err != nil {
		t.Fatal(err)
	}
	e, err := s2.Get("seed-1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusRevoked {
		t.Fatalf("seed resurrected: %+v", e)
	}
}

func TestStoreDuplicateIDAndToken(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("a", "spt_same", "one", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("a", "spt_other", "two", nil); err != ErrAlreadyExists {
		t.Fatalf("dup id err=%v", err)
	}
	if _, err := s.Add("b", "spt_same", "two", nil); err == nil {
		t.Fatal("expected duplicate token error")
	}
}
