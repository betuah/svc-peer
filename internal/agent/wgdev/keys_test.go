// Unit tests: WG keygen and peer config conversion.

package wgdev

import (
	"testing"

	"github.com/betuah/svc-peer/internal/protocol"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == "" || pub == "" {
		t.Fatal("empty keys")
	}
	hex, err := KeyToHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(hex) != 64 {
		t.Fatalf("hex len %d", len(hex))
	}
	_ = pub
}

func TestPeersToWG(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	out, err := peersToWG([]protocol.PeerConfig{{
		AgentID:             "a1",
		PublicKey:           pub,
		AllowedIPs:          []string{"10.10.0.5/32"},
		Endpoint:            "203.0.113.10:51820",
		PersistentKeepalive: 25,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d peers", len(out))
	}
	if out[0].Endpoint == nil || out[0].Endpoint.Port != 51820 {
		t.Fatalf("endpoint: %+v", out[0].Endpoint)
	}
	if len(out[0].AllowedIPs) != 1 {
		t.Fatal("allowed ips")
	}
}
