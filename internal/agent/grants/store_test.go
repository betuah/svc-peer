package grants

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistAddRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	created, err := s.Add("g1", "edge-a", "edge-b")
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "g1" || created.Status != StatusActive {
		t.Fatalf("created=%+v", created)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); err != nil {
		t.Fatalf("expected grants.json: %v", err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	list := s2.List()
	if len(list) != 1 || list[0].ID != "g1" || list[0].AgentAID != "edge-a" {
		t.Fatalf("reload=%+v", list)
	}

	if _, err := s2.Add("", "edge-a", "edge-b"); err == nil {
		t.Fatal("duplicate pair must fail")
	}
	if _, err := s2.Add("g1", "edge-c", "edge-d"); err != ErrAlreadyExists {
		t.Fatalf("dup id err=%v", err)
	}
	if _, err := s2.Add("", "same", "same"); err != ErrInvalid {
		t.Fatalf("self grant err=%v", err)
	}

	revoked, err := s2.Revoke("g1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt == nil {
		t.Fatalf("revoked=%+v", revoked)
	}
	if len(s2.Active()) != 0 {
		t.Fatalf("active after revoke=%+v", s2.Active())
	}
	if got := s2.RevokedIDs(); len(got) != 1 || got[0] != "g1" {
		t.Fatalf("revoked ids=%v", got)
	}

	// After revoke, same pair can be granted again under a new id.
	again, err := s2.Add("g2", "edge-b", "edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != StatusActive || len(s2.Active()) != 1 {
		t.Fatalf("re-grant=%+v active=%+v", again, s2.Active())
	}
}

func TestStoreGeneratedID(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Add("", "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	if e.ID == "" {
		t.Fatal("expected generated id")
	}
}
