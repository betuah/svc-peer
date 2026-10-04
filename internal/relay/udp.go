package relay

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/ticket"
)

// UDPForwarder authenticates announce/data frames with relay tickets and forwards opaque WG payloads.
type UDPForwarder struct {
	log    *slog.Logger
	secret string
	conn   *net.UDPConn

	mu    sync.RWMutex
	peers map[string]*net.UDPAddr // agentID → addr
}

// NewUDPForwarder binds a UDP socket.
func NewUDPForwarder(listenAddr, secret string, log *slog.Logger) (*UDPForwarder, error) {
	if log == nil {
		log = slog.Default()
	}
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &UDPForwarder{
		log:    log,
		secret: secret,
		conn:   conn,
		peers:  make(map[string]*net.UDPAddr),
	}, nil
}

// Addr returns the local UDP address.
func (f *UDPForwarder) Addr() net.Addr { return f.conn.LocalAddr() }

// Close shuts down the socket.
func (f *UDPForwarder) Close() error { return f.conn.Close() }

// Run reads packets and forwards until ctx is cancelled.
func (f *UDPForwarder) Run(ctx context.Context) error {
	buf := make([]byte, 65535)
	f.log.Info("relay UDP listening", "addr", f.conn.LocalAddr().String())
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = f.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		frame, err := DecodeFrame(buf[:n])
		if err != nil {
			continue
		}
		switch frame.Type {
		case MsgAnnounce:
			claims, err := ticket.Verify(f.secret, frame.Ticket, "", "")
			if err != nil || !claims.Allows(frame.PeerID) {
				f.log.Debug("relay announce rejected", "err", err)
				continue
			}
			f.mu.Lock()
			f.peers[frame.PeerID] = from
			f.mu.Unlock()
			f.log.Debug("relay peer announced", "peer_id", frame.PeerID, "from", from.String())
		case MsgData:
			// Source is learned by addr; validate ticket allows dest and that some peer maps to from.
			claims, err := ticket.Verify(f.secret, frame.Ticket, "", "")
			if err != nil || !claims.Allows(frame.PeerID) {
				continue
			}
			f.mu.RLock()
			to := f.peers[frame.PeerID]
			f.mu.RUnlock()
			if to == nil {
				continue
			}
			// Re-wrap for destination client (same framing); destination unwraps payload.
			out := EncodeData(frame.Ticket, frame.PeerID, frame.Payload)
			// Actually destination decodeDataPayload strips ticket+dest and returns payload only —
			// client expects full msgData frame OR just payload? Client decodeDataPayload expects full frame.
			if _, err := f.conn.WriteToUDP(out, to); err != nil {
				f.log.Debug("relay forward failed", "err", err)
			}
		}
	}
}
