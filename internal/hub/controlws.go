package hub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/betuah/svc-peer/internal/metrics"
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

// Hub is the thin NAT-bridge / signaling process for one hub_id.
type Hub struct {
	cfg     Config
	log     *slog.Logger
	tokens  *TokenStore
	reg     *Registry
	grants  *GrantStore
	netmap  *NetmapBuilder
	api     *API
	store   *FileStore
	metrics *metrics.Registry

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
	if cfg.CenterBootstrap == "" {
		return nil, fmt.Errorf("center_bootstrap is required")
	}
	if cfg.RelaySecret == "" {
		return nil, fmt.Errorf("relay_secret is required")
	}
	reg, err := NewRegistry(cfg.HubID, cfg.OverlayCIDR, cfg.DNSSuffix, time.Duration(cfg.HeartbeatTimeoutSec)*time.Second)
	if err != nil {
		return nil, err
	}
	tokens := NewTokenStore(cfg.HubID)
	if cfg.ManagementTokenSeed != "" {
		if err := tokens.SeedManagement("mgmt-bootstrap", cfg.ManagementTokenSeed); err != nil {
			return nil, err
		}
		log.Info("seeded management token (break-glass)", "hub_id", cfg.HubID)
	}

	store := NewFileStore(cfg.StatePath)
	if store != nil {
		st, err := store.Load()
		if err != nil {
			return nil, err
		}
		if st != nil {
			if st.HubID != "" && st.HubID != cfg.HubID {
				return nil, fmt.Errorf("hub state hub_id %q does not match config hub_id %q", st.HubID, cfg.HubID)
			}
			agents, err := agentsFromPersisted(st.Agents)
			if err != nil {
				return nil, err
			}
			if err := reg.RestoreAgents(agents); err != nil {
				return nil, fmt.Errorf("restore agents: %w", err)
			}
			edgeRecs := tokensFromPersisted(st.EdgeTokens)
			if err := tokens.RestoreEdge(edgeRecs); err != nil {
				return nil, fmt.Errorf("restore edge allowlist: %w", err)
			}
			log.Info("loaded durable hub state",
				"path", store.Path(),
				"agents", len(agents),
				"edge_tokens", len(edgeRecs),
				"center_agent_id", reg.CenterAgentID(),
			)
		} else {
			log.Info("durable hub state enabled (empty)", "path", store.Path())
		}
	}

	grants := NewGrantStore()
	h := &Hub{
		cfg:     cfg,
		log:     log.With("component", "hub", "hub_id", cfg.HubID),
		tokens:  tokens,
		reg:     reg,
		grants:  grants,
		netmap:  NewNetmapBuilder(reg, grants),
		store:   store,
		metrics: metrics.NewRegistry(),
		conns:   make(map[string]*Conn),
	}
	h.registerMetrics()
	h.api = &API{
		cfg:    cfg,
		tokens: tokens,
		reg:    reg,
		grants: grants,
		netmap: h.netmap,
		log:    h.log,
		hub:    h,
	}
	return h, nil
}

// Metrics returns the Prometheus registry (GET /metrics).
func (h *Hub) Metrics() *metrics.Registry { return h.metrics }

// WSConnCount returns the number of active agent control WebSocket connections.
func (h *Hub) WSConnCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// Persist writes allowlist cache + registered agents to StatePath (no-op if unset).
func (h *Hub) Persist() error {
	if h.store == nil {
		return nil
	}
	agents := h.reg.SnapshotAgents()
	pa := make([]persistedAgent, 0, len(agents))
	for _, a := range agents {
		pa = append(pa, persistedAgent{
			ID:           a.ID,
			HubID:        a.HubID,
			Role:         a.Role,
			Name:         a.Name,
			PublicKey:    a.PublicKey,
			OverlayIP:    a.OverlayIP.String(),
			DNSName:      a.DNSName,
			Tags:         append([]string(nil), a.Tags...),
			Capabilities: append([]string(nil), a.Capabilities...),
			Platform:     a.Platform,
			WGBackend:    a.WGBackend,
			TokenID:      a.TokenID,
		})
	}
	edge := h.tokens.SnapshotEdge()
	pt := make([]persistedToken, 0, len(edge))
	for _, rec := range edge {
		pt = append(pt, persistedToken{
			ID:        rec.ID,
			HubID:     rec.HubID,
			Role:      rec.Role,
			Label:     rec.Label,
			Tags:      append([]string(nil), rec.Tags...),
			Hash:      rec.Hash,
			AgentID:   rec.AgentID,
			Revoked:   rec.Revoked,
			CreatedAt: rec.CreatedAt,
		})
	}
	return h.store.Save(&stateFile{
		HubID:      h.cfg.HubID,
		Agents:     pa,
		EdgeTokens: pt,
	})
}

// persistOrLog saves durable state; logs failures without failing the request path.
func (h *Hub) persistOrLog() {
	if err := h.Persist(); err != nil {
		h.log.Error("persist hub state failed", "err", err, "path", h.store.Path())
	}
}

func agentsFromPersisted(in []persistedAgent) ([]Agent, error) {
	out := make([]Agent, 0, len(in))
	for _, p := range in {
		prefix, err := netip.ParsePrefix(p.OverlayIP)
		if err != nil {
			// Accept bare IP as /32.
			addr, aerr := netip.ParseAddr(p.OverlayIP)
			if aerr != nil {
				return nil, fmt.Errorf("agent %s overlay_ip: %w", p.ID, err)
			}
			prefix = netip.PrefixFrom(addr, 32)
		}
		out = append(out, Agent{
			ID:           p.ID,
			HubID:        p.HubID,
			Role:         p.Role,
			Name:         p.Name,
			PublicKey:    p.PublicKey,
			OverlayIP:    prefix,
			DNSName:      p.DNSName,
			Tags:         append([]string(nil), p.Tags...),
			Capabilities: append([]string(nil), p.Capabilities...),
			Platform:     p.Platform,
			WGBackend:    p.WGBackend,
			TokenID:      p.TokenID,
		})
	}
	return out, nil
}

func tokensFromPersisted(in []persistedToken) []TokenRecord {
	out := make([]TokenRecord, 0, len(in))
	for _, p := range in {
		out = append(out, TokenRecord{
			ID:        p.ID,
			HubID:     p.HubID,
			Role:      p.Role,
			Label:     p.Label,
			Tags:      append([]string(nil), p.Tags...),
			Hash:      p.Hash,
			AgentID:   p.AgentID,
			Revoked:   p.Revoked,
			CreatedAt: p.CreatedAt,
		})
	}
	return out
}

// API returns the HTTP API for router mounting.
func (h *Hub) API() *API { return h.api }

// Tokens exposes the token store (tests / wiring).
func (h *Hub) Tokens() *TokenStore { return h.tokens }

// Registry exposes the agent registry (tests / wiring).
func (h *Hub) Registry() *Registry { return h.reg }

// Grants exposes the grant store (tests / wiring).
func (h *Hub) Grants() *GrantStore { return h.grants }

// Netmap exposes the netmap builder (tests / wiring).
func (h *Hub) Netmap() *NetmapBuilder { return h.netmap }

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

	agentID, err := h.authenticateWS(hello)
	if err != nil {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "unauthorized", Message: err.Error()})
		return
	}
	if hello.HubID != "" && hello.HubID != h.cfg.HubID {
		_ = c.WriteJSON(protocol.Envelope{Type: protocol.TypeError, Code: "hub_mismatch", Message: "hub_id mismatch"})
		return
	}

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
			h.pushAllowedPeers(agentID)
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

func (h *Hub) authenticateWS(hello protocol.Envelope) (string, error) {
	if hello.Token == "" {
		return "", fmt.Errorf("token required")
	}
	if hello.Token == h.cfg.CenterBootstrap {
		cid := h.reg.CenterAgentID()
		if cid == "" {
			return "", fmt.Errorf("register center before opening control ws")
		}
		if hello.AgentID != "" && hello.AgentID != cid {
			return "", fmt.Errorf("agent_id does not match center")
		}
		return cid, nil
	}
	rec, err := h.tokens.Lookup(hello.Token)
	if err != nil || rec.Role != RoleEdgeToken {
		return "", fmt.Errorf("invalid edge join token")
	}
	if rec.AgentID == "" {
		return "", fmt.Errorf("register before opening control ws")
	}
	if hello.AgentID != "" && hello.AgentID != rec.AgentID {
		return "", fmt.Errorf("agent_id does not match token binding")
	}
	return rec.AgentID, nil
}

// coordinatePunch exchanges ranked candidates only for allowed pairs (edge↔center or grants).
// Candidates are ordered private/underlay host → other host → STUN reflexive.
func (h *Hub) coordinatePunch(reporterID string) {
	reporter, err := h.reg.Get(reporterID)
	if err != nil || len(reporter.Endpoints) == 0 {
		return
	}
	for _, other := range h.reg.SnapshotAgents() {
		if other.ID == reporterID || !other.Online || len(other.Endpoints) == 0 {
			continue
		}
		if !h.netmap.AllowedPeer(reporterID, other.ID) {
			continue
		}
		h.sendTo(reporterID, protocol.Envelope{
			Type:       protocol.TypePunch,
			PeerID:     other.ID,
			Candidates: protocol.RankEndpoints(other.Endpoints),
		})
		h.sendTo(other.ID, protocol.Envelope{
			Type:       protocol.TypePunch,
			PeerID:     reporterID,
			Candidates: protocol.RankEndpoints(reporter.Endpoints),
		})
	}
}

func (h *Hub) issueRelayTicket(conn *Conn, agentID, peerID string) {
	if peerID == "" {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "bad_relay_request", Message: "peer_id required"})
		return
	}
	if !h.netmap.AllowedPeer(agentID, peerID) {
		_ = conn.send(protocol.Envelope{Type: protocol.TypeError, Code: "forbidden", Message: "peer pair not allowed"})
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

// PushNetmapTo pushes ACL-derived netmap to the listed agents.
func (h *Hub) PushNetmapTo(agentIDs ...string) {
	for _, id := range agentIDs {
		if id == "" {
			continue
		}
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

func (h *Hub) pushAllowedPeers(agentID string) {
	ids := []string{agentID}
	for _, other := range h.reg.SnapshotAgents() {
		if other.ID == agentID {
			continue
		}
		if h.netmap.AllowedPeer(agentID, other.ID) {
			ids = append(ids, other.ID)
		}
	}
	h.PushNetmapTo(ids...)
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
