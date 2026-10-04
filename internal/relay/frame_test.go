package relay

import (
	"testing"
	"time"

	"github.com/betuah/svc-peer/internal/ticket"
)

func TestDecodeAnnounceAndData(t *testing.T) {
	tok, _, err := ticket.Issue("secret", "aaa", "bbb", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ann := encodeAnnounceForTest(tok, "aaa")
	f, err := DecodeFrame(ann)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != MsgAnnounce || f.PeerID != "aaa" || f.Ticket != tok {
		t.Fatalf("announce mismatch: %+v", f)
	}
	data := EncodeData(tok, "bbb", []byte{1, 2, 3, 4})
	f2, err := DecodeFrame(data)
	if err != nil {
		t.Fatal(err)
	}
	if f2.Type != MsgData || f2.PeerID != "bbb" || string(f2.Payload) != "\x01\x02\x03\x04" {
		t.Fatalf("data mismatch: %+v", f2)
	}
}

func encodeAnnounceForTest(ticket, agentID string) []byte {
	// mirror client announce framing
	tb := []byte(ticket)
	pb := []byte(agentID)
	out := make([]byte, 1+2+len(tb)+2+len(pb))
	out[0] = MsgAnnounce
	out[1] = byte(len(tb) >> 8)
	out[2] = byte(len(tb))
	copy(out[3:], tb)
	off := 3 + len(tb)
	out[off] = byte(len(pb) >> 8)
	out[off+1] = byte(len(pb))
	copy(out[off+2:], pb)
	return out
}
