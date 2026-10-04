package hub

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // MVP; tighten with TLS + origin checks later
}

// Conn tracks a connected agent control channel.
type Conn struct {
	AgentID string
	conn    *websocket.Conn
	mu      sync.Mutex
}

func (c *Conn) send(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

// Hub is the control-plane process wiring REST + WS + registry.
type Hub struct {
	cfg    Config
	log    *slog.Logger
	tokens *TokenStore
	reg    *Registry
	netmap *NetmapBuilder
	api    *API

	mu    sync.RWMutex
	conns map[string]*Conn // agentID → conn
}

// New creates a hub from config.
func New(cfg Config, log *slog.Logger) (*Hub, error) {
	if log == nil {
		log = slog.Default()
	}
	reg, err := NewRegistry(cfg.OverlayCIDR, cfg.DNSSuffix, time.Duration(cfg.HeartbeatTimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	tokens := NewTokenStore()
	for _, ps := range cfg.PreSeedTokens {
		if err := tokens.Seed(ps.ID, ps.Token, ps.Label, ps.Tags); err != nil {
			return nil, err
		}
		log.Info("pre-seeded token", "id", ps.ID, "label", ps.Label)
	}
	h := &Hub{
		cfg:    cfg,
		log:    log,
		tokens: tokens,
		reg:    reg,
		netmap: NewNetmapBuilder(reg),
		conns:  make(map[string]*Conn),
	}
	h.api = &API{
		cfg:    cfg,
		tokens: tokens,
		reg:    reg,
		netmap: h.netmap,
		log:    log,
		hub:    h,
	}
	return h, nil
}

// API returns the HTTP API for router mounting.
func (h *Hub) API() *API { return h.api }

// Tokens exposes the token store (tests / wiring).
func (h *Hub) Tokens() *TokenStore { return h.tokens }

// Registry exposes the agent registry (tests / wiring).
func (h *Hub) Registry() *Registry { return h.reg }

// HandleAgentWS upgrades to the agent control WebSocket.
func (h *Hub) HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	c, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("ws upgrade failed", "err", err)
		return
	}
	defer c.Close()

	// First message must be hello with token (prefer over query string).
	_, data, err := c.ReadMessage()
	if err != nil {
		return
	}
	var hello protocol.Envelope
	if err := json.Unmarshal(data, &hello); err != nil || hello.Type != protocol.TypeHello {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "bad_hello", Message: "first message must be hello"})
		return
	}
	rec, err := h.tokens.Lookup(hello.Token)
	if err != nil {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "unauthorized", Message: "invalid token"})
		return
	}
	if rec.AgentID == "" {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "not_registered", Message: "register before opening control ws"})
		return
	}
	if hello.AgentID != "" && hello.AgentID != rec.AgentID {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "agent_mismatch", Message: "agent_id does not match token binding"})
		return
	}

	agentID := rec.AgentID
	conn := &Conn{AgentID: agentID, conn: c}
	h.mu.Lock()
	if old, ok := h.conns[agentID]; ok {
		_ = old.conn.Close()
	}
	h.conns[agentID] = conn
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if cur, ok := h.conns[agentID]; ok && cur == conn {
			delete(h.conns, agentID)
		}
		h.mu.Unlock()
		h.reg.SetOffline(agentID)
		h.log.Info("agent ws disconnected", "agent_id", agentID)
	}()

	_ = h.reg.Heartbeat(agentID)
	nm := h.netmap.ForAgent(agentID)
	_ = conn.send(protocol.Envelope{
		Type:     protocol.TypeNetmap,
		Revision: nm.Revision,
		Peers:    nm.Peers,
		DNSMap:   nm.DNSMap,
	})
	_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "hello_ok"})
	h.log.Info("agent ws connected", "agent_id", agentID)

	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "bad_json", Message: "invalid message"})
			continue
		}
		switch env.Type {
		case protocol.TypeHeartbeat:
			_ = h.reg.Heartbeat(agentID)
			_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "heartbeat"})
		case protocol.TypeEndpointReport:
			if err := h.reg.UpdateEndpoints(agentID, env.Endpoints); err != nil {
				_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "endpoint_update", Message: err.Error()})
				continue
			}
			// Stub: notify peers of endpoint changes via netmap push.
			h.BroadcastNetmapExcept("")
			_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "endpoints_ok"})
		case protocol.TypePathStatus:
			// Stub: accept path status for future metrics.
			_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "path_status_ok"})
		default:
			_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "unknown_type", Message: env.Type})
		}
	}
}

// BroadcastNetmapExcept pushes current netmap to all connected agents except skipID (empty = none).
func (h *Hub) BroadcastNetmapExcept(skipID string) {
	h.mu.RLock()
	conns := make([]*Conn, 0, len(h.conns))
	for id, c := range h.conns {
		if id == skipID {
			continue
		}
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	for _, c := range conns {
		nm := h.netmap.ForAgent(c.AgentID)
		_ = c.send(protocol.Envelope{
			Type:     protocol.TypeNetmap,
			Revision: nm.Revision,
			Peers:    nm.Peers,
			DNSMap:   nm.DNSMap,
		})
	}
}

// StartPresenceSweeper periodically marks stale agents offline.
func (h *Hub) StartPresenceSweeper(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			flipped := h.reg.SweepOffline()
			for _, id := range flipped {
				h.log.Info("agent marked offline (heartbeat timeout)", "agent_id", id)
			}
		}
	}
}
