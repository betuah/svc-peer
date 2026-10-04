package relay

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// PacketHeaderSize is scaffold framing: [16-byte dest peer id][opaque WG payload].
const PacketHeaderSize = 16

// UDPForwarder is a minimal opaque packet forwarder for WireGuard UDP.
// Agents announce themselves (dest id all-zero + src id in payload); subsequent packets
// are forwarded to the last known address for the destination peer id.
// Ticket authentication against the hub is TODO (Phase 2).
type UDPForwarder struct {
	log  *slog.Logger
	conn *net.UDPConn

	mu    sync.RWMutex
	peers map[string]*net.UDPAddr // peerID → addr
}

// NewUDPForwarder binds a UDP socket.
func NewUDPForwarder(listenAddr string, log *slog.Logger) (*UDPForwarder, error) {
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
		log:   log,
		conn:  conn,
		peers: make(map[string]*net.UDPAddr),
	}, nil
}

// Addr returns the local UDP address.
func (f *UDPForwarder) Addr() net.Addr { return f.conn.LocalAddr() }

// Close shuts down the socket.
func (f *UDPForwarder) Close() error { return f.conn.Close() }

// Run reads packets and forwards opaque payloads until ctx is cancelled.
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
		if n < PacketHeaderSize {
			continue
		}
		destID := string(buf[:PacketHeaderSize])
		payload := append([]byte(nil), buf[PacketHeaderSize:n]...)

		// Announce: dest all zeros → register source peer id from first 16 payload bytes.
		if isZeroID(destID) {
			if len(payload) < PacketHeaderSize {
				continue
			}
			srcID := string(payload[:PacketHeaderSize])
			f.mu.Lock()
			f.peers[srcID] = from
			f.mu.Unlock()
			f.log.Debug("relay peer announced", "from", from.String())
			continue
		}

		f.mu.RLock()
		to := f.peers[destID]
		f.mu.RUnlock()
		if to == nil {
			continue
		}
		if _, err := f.conn.WriteToUDP(payload, to); err != nil {
			f.log.Debug("relay forward failed", "err", err)
		}
	}
}

func isZeroID(id string) bool {
	for i := 0; i < len(id); i++ {
		if id[i] != 0 {
			return false
		}
	}
	return true
}
