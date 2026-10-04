package relay

import (
	"encoding/binary"
	"fmt"
)

const (
	MsgAnnounce byte = 1
	MsgData     byte = 2
)

// Frame is a decoded relay packet.
type Frame struct {
	Type    byte
	Ticket  string
	PeerID  string // announce: self; data: destination
	Payload []byte
}

// DecodeFrame parses announce/data framing.
func DecodeFrame(b []byte) (*Frame, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("short frame")
	}
	typ := b[0]
	tlen := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+tlen+2 {
		return nil, fmt.Errorf("short ticket")
	}
	ticket := string(b[3 : 3+tlen])
	off := 3 + tlen
	plen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if len(b) < off+plen {
		return nil, fmt.Errorf("short peer id")
	}
	peerID := string(b[off : off+plen])
	off += plen
	switch typ {
	case MsgAnnounce:
		return &Frame{Type: typ, Ticket: ticket, PeerID: peerID}, nil
	case MsgData:
		return &Frame{Type: typ, Ticket: ticket, PeerID: peerID, Payload: append([]byte(nil), b[off:]...)}, nil
	default:
		return nil, fmt.Errorf("unknown type %d", typ)
	}
}

// EncodeData builds a data frame (used when forwarding to WS peers as-is from UDP, etc.).
func EncodeData(ticket, destID string, payload []byte) []byte {
	tb := []byte(ticket)
	db := []byte(destID)
	out := make([]byte, 1+2+len(tb)+2+len(db)+len(payload))
	out[0] = MsgData
	binary.BigEndian.PutUint16(out[1:], uint16(len(tb)))
	copy(out[3:], tb)
	off := 3 + len(tb)
	binary.BigEndian.PutUint16(out[off:], uint16(len(db)))
	copy(out[off+2:], db)
	copy(out[off+2+len(db):], payload)
	return out
}
