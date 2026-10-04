package hub

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/betuah/svc-peer/internal/ticket"
	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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
	conns map[string]*Conn
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
			h.BroadcastNetmapExcept("")
			h.coordinatePunch(agentID)
			_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "endpoints_ok"})
		case protocol.TypePathStatus:
			h.log.Info("path status", "agent_id", agentID, "peer_id", env.PeerID, "path", env.Path, "rtt_ms", env.RTTMs)
			_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "path_status_ok"})
		case protocol.TypeRelayRequest:
			h.issueRelayTicket(conn, agentID, env.PeerID)
		default:
			_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "unknown_type", Message: env.Type})
		}
	}
}

func (h *Hub) coordinatePunch(reporterID string) {
	reporter, err := h.reg.Get(reporterID)
	if err != nil || len(reporter.Endpoints) == 0 {
		return
	}
	agents := h.reg.SnapshotAgents()
	for _, other := range agents {
		if other.ID == reporterID || !other.Online || len(other.Endpoints) == 0 {
			continue
		}
		h.sendTo(reporterID, protocol.Envelope{
			Type:       protocol.TypePunch,
			PeerID:     other.ID,
			Candidates: other.Endpoints,
		})
		h.sendTo(other.ID, protocol.Envelope{
			Type:       protocol.TypePunch,
			PeerID:     reporterID,
			Candidates: reporter.Endpoints,
		})
	}
}

func (h *Hub) issueRelayTicket(conn *Conn, agentID, peerID string) {
	if peerID == "" {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "bad_relay_request", Message: "peer_id required"})
		return
	}
	if _, err := h.reg.Get(peerID); err != nil {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "unknown_peer", Message: peerID})
		return
	}
	tok, exp, err := ticket.Issue(h.cfg.HubSecret, agentID, peerID, 10*time.Minute)
	if err != nil {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "ticket_issue", Message: err.Error()})
		return
	}
	msg := protocol.Envelope{
		Type:      protocol.TypeRelayTicket,
		PeerID:    peerID,
		URLs:      h.cfg.RelayURLs,
		Ticket:    tok,
		ExpiresAt: exp.Format(time.RFC3339),
	}
	_ = conn.send(msg)
	// Peer receives the same ticket with PeerID pointing at the requester.
	toPeer := msg
	toPeer.PeerID = agentID
	h.sendTo(peerID, toPeer)
	h.log.Info("relay ticket issued", "agent_id", agentID, "peer_id", peerID)
}

func (h *Hub) sendTo(agentID string, env protocol.Envelope) {
	h.mu.RLock()
	c := h.conns[agentID]
	h.mu.RUnlock()
	if c == nil {
		return
	}
	_ = c.send(env)
}

// BroadcastNetmapExcept pushes current netmap to all connected agents except skipID.
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
