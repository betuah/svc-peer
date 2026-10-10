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
	stats  *relayStats

	mu    sync.RWMutex
	peers map[string]*net.UDPAddr // agentID → addr
}

// NewUDPForwarder binds a UDP socket.
func NewUDPForwarder(listenAddr, secret string, log *slog.Logger, stats *relayStats) (*UDPForwarder, error) {
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
		stats:  stats,
		peers:  make(map[string]*net.UDPAddr),
	}, nil
}

// Addr returns the local UDP address.
func (f *UDPForwarder) Addr() net.Addr { return f.conn.LocalAddr() }

// Close shuts down the socket.
func (f *UDPForwarder) Close() error { return f.conn.Close() }

// PeerCount returns announced UDP peers.
func (f *UDPForwarder) PeerCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.peers)
}

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
			_, existed := f.peers[frame.PeerID]
			f.peers[frame.PeerID] = from
			nPeers := len(f.peers)
			f.mu.Unlock()
			if f.stats != nil {
				f.stats.udpPeers.Store(int64(nPeers))
				if !existed {
					f.log.Debug("relay peer announced", "peer_id", frame.PeerID, "from", from.String())
				}
			} else {
				f.log.Debug("relay peer announced", "peer_id", frame.PeerID, "from", from.String())
			}
		case MsgData:
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
			out := EncodeData(frame.Ticket, frame.PeerID, frame.Payload)
			if _, err := f.conn.WriteToUDP(out, to); err != nil {
				f.log.Debug("relay forward failed", "err", err)
				continue
			}
			if f.stats != nil {
				f.stats.forwards.Inc("transport", "udp")
				f.stats.bytes.Add(uint64(len(frame.Payload)), "transport", "udp")
			}
		}
	}
}
