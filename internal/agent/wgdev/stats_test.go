package wgdev

import (
	"testing"
	"time"
)

func TestParseUserspacePeerStats(t *testing.T) {
	const pkHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	const pubB64 = "qrvM3e7/ABEiM0RVZneImaurzN3u/wARIjNFVWZ3iJk="
	ipc := "private_key=00\n" +
		"public_key=" + pkHex + "\n" +
		"endpoint=203.0.113.10:51820\n" +
		"last_handshake_time_sec=1700000000\n" +
		"rx_bytes=111\n" +
		"tx_bytes=222\n" +
		"public_key=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n" +
		"rx_bytes=9\n" +
		"tx_bytes=8\n"

	st, ok := parseUserspacePeerStats(ipc, pkHex, pubB64)
	if !ok {
		t.Fatal("expected peer found")
	}
	if st.ReceiveBytes != 111 || st.TransmitBytes != 222 {
		t.Fatalf("tx/rx: got tx=%d rx=%d", st.TransmitBytes, st.ReceiveBytes)
	}
	if st.Endpoint != "203.0.113.10:51820" {
		t.Fatalf("endpoint=%q", st.Endpoint)
	}
	if !st.LastHandshake.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("handshake=%v", st.LastHandshake)
	}
}

func TestParseUserspacePeerStatsMissing(t *testing.T) {
	_, ok := parseUserspacePeerStats("public_key=aa\nrx_bytes=1\n", "bb", "x")
	if ok {
		t.Fatal("expected not found")
	}
}
