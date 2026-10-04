// Package ticket provides HMAC-signed short-lived relay session tickets.
package ticket

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidTicket = errors.New("invalid relay ticket")
	ErrExpiredTicket = errors.New("relay ticket expired")
	ErrPeerMismatch  = errors.New("ticket not valid for peer pair")
)

// Claims is the signed ticket body.
type Claims struct {
	PeerA string `json:"peer_a"` // lexicographically smaller agent ID
	PeerB string `json:"peer_b"`
	Exp   int64  `json:"exp"` // unix seconds
}

// NormalizePair returns (a,b) sorted so tickets are bidirectional.
func NormalizePair(agentA, agentB string) (string, string) {
	if agentA <= agentB {
		return agentA, agentB
	}
	return agentB, agentA
}

// Issue creates a ticket valid for ttl for the agent pair.
func Issue(secret, agentA, agentB string, ttl time.Duration) (string, time.Time, error) {
	if secret == "" {
		return "", time.Time{}, fmt.Errorf("ticket secret required")
	}
	if agentA == "" || agentB == "" || agentA == agentB {
		return "", time.Time{}, fmt.Errorf("invalid peer pair")
	}
	a, b := NormalizePair(agentA, agentB)
	exp := time.Now().UTC().Add(ttl)
	claims := Claims{PeerA: a, PeerB: b, Exp: exp.Unix()}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	sig := mac.Sum(nil)
	tok := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return tok, exp, nil
}

// Verify checks signature and expiry; optionally that agentID is one of the peers
// and peerID is the other.
func Verify(secret, raw, agentID, peerID string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidTicket
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidTicket
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidTicket
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrInvalidTicket
	}
	var claims Claims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, ErrInvalidTicket
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return nil, ErrExpiredTicket
	}
	if agentID != "" || peerID != "" {
		a, b := NormalizePair(agentID, peerID)
		if a != claims.PeerA || b != claims.PeerB {
			return nil, ErrPeerMismatch
		}
	}
	return &claims, nil
}

// Allows reports whether agentID is a party on the ticket.
func (c *Claims) Allows(agentID string) bool {
	return agentID == c.PeerA || agentID == c.PeerB
}

// Other returns the peer that is not agentID.
func (c *Claims) Other(agentID string) (string, bool) {
	switch agentID {
	case c.PeerA:
		return c.PeerB, true
	case c.PeerB:
		return c.PeerA, true
	default:
		return "", false
	}
}
