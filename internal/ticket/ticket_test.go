package ticket

import (
	"testing"
	"time"
)

func TestIssueVerifyRoundTrip(t *testing.T) {
	tok, exp, err := Issue("secret", "b-agent", "a-agent", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("expiry in past")
	}
	claims, err := Verify("secret", tok, "a-agent", "b-agent")
	if err != nil {
		t.Fatal(err)
	}
	if claims.PeerA != "a-agent" || claims.PeerB != "b-agent" {
		t.Fatalf("pair not normalized: %+v", claims)
	}
	// reverse order still ok
	if _, err := Verify("secret", tok, "b-agent", "a-agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify("wrong", tok, "a-agent", "b-agent"); err == nil {
		t.Fatal("expected bad secret failure")
	}
	if _, err := Verify("secret", tok, "a-agent", "c-agent"); err == nil {
		t.Fatal("expected peer mismatch")
	}
}

func TestExpiredTicket(t *testing.T) {
	tok, _, err := Issue("secret", "a", "b", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify("secret", tok, "a", "b"); err != ErrExpiredTicket {
		t.Fatalf("got %v want expired", err)
	}
}
