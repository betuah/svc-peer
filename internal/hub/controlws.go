package hub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/betuah/svc-peer/internal/ticket"
	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

// Hub is the control-plane process wiring REST + WS + registry for one hub_id.
type Hub struct {
	cfg    Config
	log    *slog.Logger
	tokens *TokenStore
	reg    *Registry
	grants *GrantStore
	netmap *NetmapBuilder
	api    *API
	hubPeer HubPeer

	mu    sync.RWMutex
	conns map[string]*Conn
}

// New creates a hub from config.
func New(cfg Config, log *slog.Logger) (*Hub, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.HubID == "" {
		return nil, fmt.Errorf("hub_id is required")
	}
	if cfg.ManagementTokenSeed == "" {
		return nil, fmt.Errorf("management_token_seed is required")
	}
	if cfg.RelaySecret == "" {
		return nil, fmt.Errorf("relay_secret is required")
	}
	reg, err := NewRegistry(cfg.HubID, cfg.OverlayCIDR, cfg.DNSSuffix, time.Duration(cfg.HeartbeatTimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	tokens := NewTokenStore(cfg.HubID)
	if err := tokens.SeedManagement("mgmt-bootstrap", cfg.ManagementTokenSeed); err != nil {
		return nil, err
	}
	log.Info("seeded management token", "hub_id", cfg.HubID, "id", "mgmt-bootstrap")
	for _, ps := range cfg.PreSeedTokens {
		if err := tokens.Seed(ps.ID, ps.Token, ps.Label, ps.Tags); err != nil {
			return nil, err
		}
		log.Info("pre-seeded agent token", "hub_id", cfg.HubID, "id", ps.ID, "label", ps.Label)
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate hub wg key: %w", err)
	}
	hubPeer := HubPeer{
		PeerID:    PeerIDHub,
		PublicKey: priv.PublicKey().String(),
		Endpoint:  cfg.HubEndpoint,
		OverlayIP: reg.HubOverlayIP().String(),
		DNSName:   "hub." + cfg.DNSSuffix,
	}

	grants := NewGrantStore()
	h := &Hub{
		cfg:     cfg,
		log:     log,
		tokens:  tokens,
		reg:     reg,
		grants:  grants,
		netmap:  NewNetmapBuilder(reg, grants, hubPeer),
		hubPeer: hubPeer,
		conns:   make(map[string]*Conn),
	}
	h.api = &API{
		cfg:    cfg,
		tokens: tokens,
		reg:    reg,
		grants: grants,
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

// Grants exposes the grant store (tests / wiring).
func (h *Hub) Grants() *GrantStore { return h.grants }

// HubPeer returns the hub WG identity advertised in agent netmaps.
func (h *Hub) HubPeer() HubPeer { return h.hubPeer }

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
	if err != nil || rec.Role != RoleAgent {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "unauthorized", Message: "invalid agent token"})
		return
	}
	if rec.HubID != h.cfg.HubID || (hello.HubID != "" && hello.HubID != h.cfg.HubID) {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "hub_mismatch", Message: "token/hub_id mismatch"})
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
		h.log.Info("agent ws disconnected", "hub_id", h.cfg.HubID, "agent_id", agentID)
	}()

	_ = h.reg.Heartbeat(agentID)
	nm := h.netmap.ForAgent(agentID)
	_ = conn.send(protocol.Envelope{
		Type:     protocol.TypeNetmap,
		HubID:    h.cfg.HubID,
		Revision: nm.Revision,
		Peers:    nm.Peers,
		DNSMap:   nm.DNSMap,
	})
	_ = conn.send(protocol.Envelope{Type: protocol.TypeAck, Message: "hello_ok"})
	h.log.Info("agent ws connected", "hub_id", h.cfg.HubID, "agent_id", agentID)

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
			h.PushNetmapToGrantedPeers(agentID)
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

// coordinatePunch exchanges candidates only for granted A2A peers (not open mesh).
func (h *Hub) coordinatePunch(reporterID string) {
	reporter, err := h.reg.Get(reporterID)
	if err != nil || len(reporter.Endpoints) == 0 {
		return
	}
	for _, otherID := range h.grants.PeersOf(reporterID) {
		other, err := h.reg.Get(otherID)
		if err != nil || !other.Online || len(other.Endpoints) == 0 {
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
	if peerID == PeerIDHub {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "relay_not_supported", Message: "relay assist for hub path not issued via A2A tickets"})
		return
	}
	if !h.grants.Allowed(agentID, peerID) {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "forbidden", Message: "no A2A grant for peer pair"})
		return
	}
	if _, err := h.reg.Get(peerID); err != nil {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "unknown_peer", Message: peerID})
		return
	}
	tok, exp, err := ticket.Issue(h.cfg.RelaySecret, agentID, peerID, 10*time.Minute)
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
	toPeer := msg
	toPeer.PeerID = agentID
	h.sendTo(peerID, toPeer)
	h.log.Info("relay ticket issued", "hub_id", h.cfg.HubID, "agent_id", agentID, "peer_id", peerID)
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

// PushNetmapTo pushes ACL-derived netmap to the listed agents (signaling-only).
func (h *Hub) PushNetmapTo(agentIDs ...string) {
	for _, id := range agentIDs {
		h.mu.RLock()
		c := h.conns[id]
		h.mu.RUnlock()
		if c == nil {
			continue
		}
		nm := h.netmap.ForAgent(id)
		_ = c.send(protocol.Envelope{
			Type:     protocol.TypeNetmap,
			HubID:    h.cfg.HubID,
			Revision: nm.Revision,
			Peers:    nm.Peers,
			DNSMap:   nm.DNSMap,
		})
	}
}

// PushNetmapToGrantedPeers updates the reporter and its granted peers after endpoint changes.
func (h *Hub) PushNetmapToGrantedPeers(agentID string) {
	ids := append([]string{agentID}, h.grants.PeersOf(agentID)...)
	h.PushNetmapTo(ids...)
}

// BroadcastNetmapExcept pushes current netmap to all connected agents except skipID.
// Prefer PushNetmapTo / PushNetmapToGrantedPeers for tight fan-out.
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
			HubID:    h.cfg.HubID,
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
				h.log.Info("agent marked offline (heartbeat timeout)", "hub_id", h.cfg.HubID, "agent_id", id)
			}
		}
	}
}
