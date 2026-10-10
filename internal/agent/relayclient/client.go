// Package relayclient dials the owned relay and shims local UDP for WireGuard endpoints.
package relayclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	msgAnnounce byte = 1
	msgData     byte = 2
)

// Client maintains a relay session (UDP preferred, WS fallback) and a local UDP shim
// so the WG device can use 127.0.0.1:<shim> as the peer endpoint.
type Client struct {
	log      *slog.Logger
	agentID  string
	ticket   string
	udpURL   string
	wsURL    string
	mu       sync.Mutex
	sessions map[string]*session // peerID → session
}

type session struct {
	peerID     string
	local      *net.UDPConn
	remote     net.Conn
	cancel     context.CancelFunc
	wgAddrMu   sync.Mutex
	wgPeerAddr *net.UDPAddr // last address WireGuard used toward the shim
}

// LocalAddr returns the shim address string for a peer session.
func (s *session) LocalAddr() string {
	return s.local.LocalAddr().String()
}

// New creates a relay client for this agent.
func New(agentID string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		log:      log,
		agentID:  agentID,
		sessions: make(map[string]*session),
	}
}

// ConfigureTicket sets the active ticket and preferred relay URLs.
func (c *Client) ConfigureTicket(ticket string, urls []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticket = ticket
	c.udpURL = ""
	c.wsURL = ""
	for _, u := range urls {
		switch {
		case strings.HasPrefix(u, "udp://"):
			if c.udpURL == "" {
				c.udpURL = strings.TrimPrefix(u, "udp://")
			}
		case strings.HasPrefix(u, "ws://"), strings.HasPrefix(u, "wss://"):
			if c.wsURL == "" {
				c.wsURL = u
			}
		}
	}
}

// EnsurePeer opens (or reuses) a shim session toward peerID. Returns local endpoint for WG.
func (c *Client) EnsurePeer(ctx context.Context, peerID string) (string, error) {
	c.mu.Lock()
	if s, ok := c.sessions[peerID]; ok {
		addr := s.LocalAddr()
		c.mu.Unlock()
		return addr, nil
	}
	ticket := c.ticket
	udpURL := c.udpURL
	wsURL := c.wsURL
	c.mu.Unlock()

	if ticket == "" {
		return "", fmt.Errorf("no relay ticket configured")
	}

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return "", err
	}

	sessCtx, cancel := context.WithCancel(ctx)
	s := &session{peerID: peerID, local: local, cancel: cancel}

	var remote net.Conn
	var dialErr error
	if udpURL != "" {
		remote, dialErr = dialUDPRelay(sessCtx, udpURL, ticket, c.agentID)
	}
	if remote == nil && wsURL != "" {
		remote, dialErr = dialWSRelay(sessCtx, wsURL, ticket, c.agentID)
	}
	if remote == nil {
		cancel()
		_ = local.Close()
		if dialErr == nil {
			dialErr = fmt.Errorf("no relay transport available")
		}
		return "", dialErr
	}
	s.remote = remote

	c.mu.Lock()
	c.sessions[peerID] = s
	c.mu.Unlock()

	go c.loopLocalToRelay(sessCtx, s)
	go c.loopRelayToLocal(sessCtx, s)

	c.log.Info("relay shim ready", "peer_id", peerID, "local", s.LocalAddr())
	return s.LocalAddr(), nil
}

// ClosePeer tears down one session.
func (c *Client) ClosePeer(peerID string) {
	c.mu.Lock()
	s, ok := c.sessions[peerID]
	if ok {
		delete(c.sessions, peerID)
	}
	c.mu.Unlock()
	if ok {
		s.cancel()
		_ = s.local.Close()
		_ = s.remote.Close()
	}
}

// CloseAll stops every session.
func (c *Client) CloseAll() {
	c.mu.Lock()
	ids := make([]string, 0, len(c.sessions))
	for id := range c.sessions {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.ClosePeer(id)
	}
}

func (c *Client) loopLocalToRelay(ctx context.Context, s *session) {
	buf := make([]byte, 65535)
	for {
		_ = s.local.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := s.local.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		s.wgAddrMu.Lock()
		s.wgPeerAddr = from
		s.wgAddrMu.Unlock()

		frame := encodeData(c.ticket, s.peerID, buf[:n])
		if _, err := s.remote.Write(frame); err != nil {
			c.log.Debug("relay write failed", "err", err)
			return
		}
	}
}

func (c *Client) loopRelayToLocal(ctx context.Context, s *session) {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = s.remote.SetReadDeadline(time.Now().Add(time.Second))
		n, err := s.remote.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if err == io.EOF {
				return
			}
			return
		}
		payload, err := decodeDataPayload(buf[:n])
		if err != nil {
			continue
		}
		s.wgAddrMu.Lock()
		to := s.wgPeerAddr
		s.wgAddrMu.Unlock()
		if to == nil {
			continue
		}
		if _, err := s.local.WriteToUDP(payload, to); err != nil {
			c.log.Debug("shim write to wg failed", "err", err)
		}
	}
}

func dialUDPRelay(ctx context.Context, hostPort, ticket, agentID string) (net.Conn, error) {
	raddr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	announce := encodeAnnounce(ticket, agentID)
	if _, err := conn.Write(announce); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go keepaliveAnnounce(ctx, conn, announce)
	return conn, nil
}

func keepaliveAnnounce(ctx context.Context, conn *net.UDPConn, announce []byte) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = conn.Write(announce)
		}
	}
}

type wsConn struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (w *wsConn) Read(p []byte) (int, error) {
	_, data, err := w.c.ReadMessage()
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if n < len(data) {
		return n, fmt.Errorf("ws frame truncated to buffer")
	}
	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error         { return w.c.Close() }
func (w *wsConn) LocalAddr() net.Addr  { return dummyAddr("ws-local") }
func (w *wsConn) RemoteAddr() net.Addr { return dummyAddr("ws-remote") }
func (w *wsConn) SetDeadline(t time.Time) error {
	_ = w.c.SetReadDeadline(t)
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

type dummyAddr string

func (d dummyAddr) Network() string { return "ws" }
func (d dummyAddr) String() string  { return string(d) }

func dialWSRelay(ctx context.Context, rawURL, ticket, agentID string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	c, _, err := dialer.DialContext(ctx, u.String(), http.Header{})
	if err != nil {
		return nil, err
	}
	hello, _ := json.Marshal(map[string]string{
		"ticket":  ticket,
		"peer_id": agentID,
	})
	if err := c.WriteMessage(websocket.TextMessage, hello); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &wsConn{c: c}, nil
}

func encodeAnnounce(ticket, agentID string) []byte {
	tb := []byte(ticket)
	pb := []byte(agentID)
	out := make([]byte, 1+2+len(tb)+2+len(pb))
	out[0] = msgAnnounce
	binary.BigEndian.PutUint16(out[1:], uint16(len(tb)))
	copy(out[3:], tb)
	off := 3 + len(tb)
	binary.BigEndian.PutUint16(out[off:], uint16(len(pb)))
	copy(out[off+2:], pb)
	return out
}

func encodeData(ticket, destID string, payload []byte) []byte {
	tb := []byte(ticket)
	db := []byte(destID)
	out := make([]byte, 1+2+len(tb)+2+len(db)+len(payload))
	out[0] = msgData
	binary.BigEndian.PutUint16(out[1:], uint16(len(tb)))
	copy(out[3:], tb)
	off := 3 + len(tb)
	binary.BigEndian.PutUint16(out[off:], uint16(len(db)))
	copy(out[off+2:], db)
	copy(out[off+2+len(db):], payload)
	return out
}

func decodeDataPayload(frame []byte) ([]byte, error) {
	if len(frame) < 5 || frame[0] != msgData {
		return nil, fmt.Errorf("not data")
	}
	tlen := int(binary.BigEndian.Uint16(frame[1:]))
	off := 3 + tlen
	if len(frame) < off+2 {
		return nil, fmt.Errorf("short")
	}
	dlen := int(binary.BigEndian.Uint16(frame[off:]))
	off += 2 + dlen
	if len(frame) < off {
		return nil, fmt.Errorf("short payload")
	}
	return append([]byte(nil), frame[off:]...), nil
}

// EncodeAnnounce exported for relay tests.
func EncodeAnnounce(ticket, agentID string) []byte { return encodeAnnounce(ticket, agentID) }

// EncodeData exported for relay tests.
func EncodeData(ticket, destID string, payload []byte) []byte {
	return encodeData(ticket, destID, payload)
}
