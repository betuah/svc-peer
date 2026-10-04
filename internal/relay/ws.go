package relay

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var relayUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSHub is a stub WebSocket/TLS relay path for firewall-hostile networks.
// Real design: authenticate short-lived hub tickets, then forward opaque WG frames
// between paired peers (same as UDP path).
type WSHub struct {
	log *slog.Logger

	mu    sync.Mutex
	peers map[string]*websocket.Conn
}

// NewWSHub creates a WS relay stub.
func NewWSHub(log *slog.Logger) *WSHub {
	if log == nil {
		log = slog.Default()
	}
	return &WSHub{
		log:   log,
		peers: make(map[string]*websocket.Conn),
	}
}

// HandleRelay upgrades a connection at /relay.
// Scaffold protocol: first text message is peer_id; subsequent binary frames are
// [16-byte dest peer id][payload]. Ticket auth is TODO.
func (h *WSHub) HandleRelay(w http.ResponseWriter, r *http.Request) {
	c, err := relayUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("relay ws upgrade failed", "err", err)
		return
	}
	defer c.Close()

	_, msg, err := c.ReadMessage()
	if err != nil {
		return
	}
	peerID := string(msg)
	if peerID == "" {
		return
	}

	h.mu.Lock()
	if old, ok := h.peers[peerID]; ok {
		_ = old.Close()
	}
	h.peers[peerID] = c
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if cur, ok := h.peers[peerID]; ok && cur == c {
			delete(h.peers, peerID)
		}
		h.mu.Unlock()
	}()

	h.log.Info("relay ws peer connected", "peer_id", peerID)
	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage || len(data) < PacketHeaderSize {
			continue
		}
		destID := string(data[:PacketHeaderSize])
		payload := data[PacketHeaderSize:]

		h.mu.Lock()
		dest := h.peers[destID]
		h.mu.Unlock()
		if dest == nil {
			continue
		}
		if err := dest.WriteMessage(websocket.BinaryMessage, payload); err != nil {
			h.log.Debug("relay ws forward failed", "err", err)
		}
	}
}
