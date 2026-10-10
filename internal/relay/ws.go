package relay

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/betuah/svc-peer/internal/ticket"
	"github.com/gorilla/websocket"
)

var relayUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WSHub forwards opaque WG frames over WebSocket with ticket auth.
type WSHub struct {
	log    *slog.Logger
	secret string
	stats  *relayStats

	mu    sync.Mutex
	peers map[string]*websocket.Conn
}

// NewWSHub creates a WS relay.
func NewWSHub(secret string, log *slog.Logger, stats *relayStats) *WSHub {
	if log == nil {
		log = slog.Default()
	}
	return &WSHub{
		log:    log,
		secret: secret,
		stats:  stats,
		peers:  make(map[string]*websocket.Conn),
	}
}

type wsHello struct {
	Ticket string `json:"ticket"`
	PeerID string `json:"peer_id"`
}

// PeerCount returns connected WS peers.
func (h *WSHub) PeerCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.peers)
}

// HandleRelay upgrades /relay connections.
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
	var hello wsHello
	if err := json.Unmarshal(msg, &hello); err != nil || hello.PeerID == "" || hello.Ticket == "" {
		return
	}
	claims, err := ticket.Verify(h.secret, hello.Ticket, "", "")
	if err != nil || !claims.Allows(hello.PeerID) {
		h.log.Debug("relay ws hello rejected", "err", err)
		return
	}

	h.mu.Lock()
	if old, ok := h.peers[hello.PeerID]; ok {
		_ = old.Close()
	}
	h.peers[hello.PeerID] = c
	nPeers := len(h.peers)
	h.mu.Unlock()
	if h.stats != nil {
		h.stats.wsPeers.Store(int64(nPeers))
	}
	defer func() {
		h.mu.Lock()
		if cur, ok := h.peers[hello.PeerID]; ok && cur == c {
			delete(h.peers, hello.PeerID)
		}
		n := len(h.peers)
		h.mu.Unlock()
		if h.stats != nil {
			h.stats.wsPeers.Store(int64(n))
		}
	}()

	h.log.Info("relay ws peer connected", "peer_id", hello.PeerID)
	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		frame, err := DecodeFrame(data)
		if err != nil || frame.Type != MsgData {
			continue
		}
		claims, err := ticket.Verify(h.secret, frame.Ticket, "", "")
		if err != nil || !claims.Allows(frame.PeerID) {
			continue
		}
		h.mu.Lock()
		dest := h.peers[frame.PeerID]
		h.mu.Unlock()
		if dest == nil {
			continue
		}
		if err := dest.WriteMessage(websocket.BinaryMessage, data); err != nil {
			h.log.Debug("relay ws forward failed", "err", err)
			continue
		}
		if h.stats != nil {
			h.stats.forwards.Inc("transport", "ws")
			h.stats.bytes.Add(uint64(len(frame.Payload)), "transport", "ws")
		}
	}
}
