package hub

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/go-chi/chi/v5"
)

// API holds HTTP handlers for the thin hub control plane.
type API struct {
	cfg    Config
	tokens *TokenStore
	reg    *Registry
	grants *GrantStore
	netmap *NetmapBuilder
	log    *slog.Logger
	hub    *Hub
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}

func (a *API) isCenterBootstrap(raw string) bool {
	return raw != "" && raw == a.cfg.CenterBootstrap
}

func (a *API) requireManagementToken(w http.ResponseWriter, r *http.Request) bool {
	raw := bearerToken(r)
	rec, err := a.tokens.Lookup(raw)
	if err != nil || rec.Role != RoleManagement {
		writeErr(w, http.StatusUnauthorized, "management token required")
		return false
	}
	return true
}

// requireCenterAuth accepts center_bootstrap after (or for) center claim.
func (a *API) requireCenterAuth(w http.ResponseWriter, r *http.Request) bool {
	raw := bearerToken(r)
	if !a.isCenterBootstrap(raw) {
		writeErr(w, http.StatusUnauthorized, "center_bootstrap required")
		return false
	}
	return true
}

func (a *API) requireEdgeOrCenterSession(w http.ResponseWriter, r *http.Request) (agentID, role string, ok bool) {
	raw := bearerToken(r)
	if a.isCenterBootstrap(raw) {
		cid := a.reg.CenterAgentID()
		if cid == "" {
			writeErr(w, http.StatusConflict, "center not registered yet")
			return "", "", false
		}
		return cid, protocol.RoleCenter, true
	}
	rec, err := a.tokens.Lookup(raw)
	if err != nil || rec.Role != RoleEdgeToken {
		writeErr(w, http.StatusUnauthorized, "invalid agent token")
		return "", "", false
	}
	if rec.AgentID == "" {
		writeErr(w, http.StatusConflict, "agent not registered yet")
		return "", "", false
	}
	return rec.AgentID, protocol.RoleEdge, true
}

// Health handles GET /health.
func (a *API) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.HealthResponse{
		Status:          "ok",
		HubID:           a.cfg.HubID,
		CenterAgentID:   a.reg.CenterAgentID(),
		AgentsConnected: a.reg.OnlineCount(),
		NetmapRevision:  a.reg.Revision(),
	})
}

// SyncAllowlist handles PUT /hub/allowlist (center → hub token sync).
func (a *API) SyncAllowlist(w http.ResponseWriter, r *http.Request) {
	if !a.requireCenterAuth(w, r) {
		return
	}
	if a.reg.CenterAgentID() == "" {
		writeErr(w, http.StatusConflict, "register center before syncing allowlist")
		return
	}
	var req protocol.AllowlistSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	recs, err := a.tokens.UpsertEdgeAllowlist(req.Tokens)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ids := make([]string, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.ID)
	}
	a.log.Info("center allowlist synced", "hub_id", a.cfg.HubID, "count", len(ids))
	if a.hub != nil {
		a.hub.persistOrLog()
	}
	writeJSON(w, http.StatusOK, protocol.AllowlistSyncResponse{
		HubID:  a.cfg.HubID,
		Upsert: len(ids),
		IDs:    ids,
	})
}

// CreateToken is break-glass mint (management only) — not primary edge onboarding UX.
func (a *API) CreateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireManagementToken(w, r) {
		return
	}
	var req protocol.CreateTokenRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
	}
	rec, raw, err := a.tokens.MintEdge(a.cfg.HubID, req.Label, req.Tags)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a.hub != nil {
		a.hub.persistOrLog()
	}
	writeJSON(w, http.StatusCreated, protocol.TokenInfo{
		ID:        rec.ID,
		HubID:     rec.HubID,
		Role:      rec.Role,
		Label:     rec.Label,
		Token:     raw,
		AgentID:   rec.AgentID,
		Revoked:   rec.Revoked,
		CreatedAt: rec.CreatedAt,
	})
}

// RevokeToken handles DELETE /hub/tokens/{id} (management break-glass or center).
func (a *API) RevokeToken(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if !a.isCenterBootstrap(raw) {
		if !a.requireManagementToken(w, r) {
			return
		}
	} else if a.reg.CenterAgentID() == "" {
		writeErr(w, http.StatusConflict, "center not registered yet")
		return
	}
	id := chi.URLParam(r, "id")
	if err := a.tokens.Revoke(id); err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			writeErr(w, http.StatusNotFound, "token not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a.hub != nil {
		a.hub.persistOrLog()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// RotateToken handles POST /hub/tokens/{id}/rotate (management break-glass).
func (a *API) RotateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireManagementToken(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	rec, raw, err := a.tokens.Rotate(id)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			writeErr(w, http.StatusNotFound, "token not found")
			return
		}
		if errors.Is(err, ErrTokenRevoked) {
			writeErr(w, http.StatusConflict, "token revoked")
			return
		}
		if errors.Is(err, ErrWrongRole) {
			writeErr(w, http.StatusBadRequest, "only edge tokens can be rotated")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a.hub != nil {
		a.hub.persistOrLog()
	}
	writeJSON(w, http.StatusOK, protocol.RotateTokenResponse{
		ID:      rec.ID,
		Token:   raw,
		AgentID: rec.AgentID,
	})
}

func (a *API) requireCenterOrManagement(w http.ResponseWriter, r *http.Request) bool {
	raw := bearerToken(r)
	if a.isCenterBootstrap(raw) {
		if a.reg.CenterAgentID() == "" {
			writeErr(w, http.StatusConflict, "center not registered yet")
			return false
		}
		return true
	}
	return a.requireManagementToken(w, r)
}

// CreateGrant handles POST /hub/grants (center-authored; management break-glass OK).
func (a *API) CreateGrant(w http.ResponseWriter, r *http.Request) {
	if !a.requireCenterOrManagement(w, r) {
		return
	}
	var req protocol.CreateGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if _, err := a.reg.Get(req.AgentAID); err != nil {
		writeErr(w, http.StatusBadRequest, "agent_a_id not found on this hub")
		return
	}
	if _, err := a.reg.Get(req.AgentBID); err != nil {
		writeErr(w, http.StatusBadRequest, "agent_b_id not found on this hub")
		return
	}
	g, created, err := a.grants.GrantWithID(req.ID, req.AgentAID, req.AgentBID)
	if err != nil {
		if errors.Is(err, ErrGrantExists) {
			writeErr(w, http.StatusConflict, "grant already exists")
			return
		}
		if errors.Is(err, ErrGrantInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if created {
		a.reg.BumpRevision()
		if a.hub != nil {
			a.hub.PushNetmapTo(req.AgentAID, req.AgentBID)
		}
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, protocol.GrantInfo{
		ID:        g.ID,
		HubID:     a.cfg.HubID,
		AgentAID:  g.AgentA,
		AgentBID:  g.AgentB,
		CreatedAt: g.CreatedAt,
	})
}

// RevokeGrant handles DELETE /hub/grants/{id}.
func (a *API) RevokeGrant(w http.ResponseWriter, r *http.Request) {
	if !a.requireCenterOrManagement(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	g, err := a.grants.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	if err := a.grants.Revoke(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.reg.BumpRevision()
	if a.hub != nil {
		a.hub.PushNetmapTo(g.AgentA, g.AgentB)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// ListGrants handles GET /hub/grants.
func (a *API) ListGrants(w http.ResponseWriter, r *http.Request) {
	if !a.requireCenterOrManagement(w, r) {
		return
	}
	raw := a.grants.List()
	out := make([]protocol.GrantInfo, 0, len(raw))
	for _, g := range raw {
		out = append(out, protocol.GrantInfo{
			ID:        g.ID,
			HubID:     a.cfg.HubID,
			AgentAID:  g.AgentA,
			AgentBID:  g.AgentB,
			CreatedAt: g.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, protocol.GrantsListResponse{
		HubID:  a.cfg.HubID,
		Grants: out,
	})
}

// Register handles POST /agents/register.
func (a *API) Register(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		writeErr(w, http.StatusUnauthorized, "authorization required")
		return
	}
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.AgentID == "" {
		writeErr(w, http.StatusBadRequest, "agent_id is required (locally generated)")
		return
	}

	var (
		agent   *Agent
		created bool
		err     error
		tokenID string
		role    string
	)

	if a.isCenterBootstrap(raw) {
		role = protocol.RoleCenter
		if req.Role != "" && req.Role != protocol.RoleCenter {
			writeErr(w, http.StatusBadRequest, "center_bootstrap may only register role=center")
			return
		}
		agent, created, err = a.reg.RegisterPresented(req.AgentID, "", protocol.RoleCenter, req)
	} else {
		rec, lerr := a.tokens.Lookup(raw)
		if lerr != nil || rec.Role != RoleEdgeToken {
			writeErr(w, http.StatusUnauthorized, "invalid edge join token")
			return
		}
		role = protocol.RoleEdge
		if req.Role != "" && req.Role != protocol.RoleEdge {
			writeErr(w, http.StatusBadRequest, "edge join token may only register role=edge")
			return
		}
		// Collision: token already bound to a different presented agent_id.
		if rec.AgentID != "" && rec.AgentID != req.AgentID {
			writeErr(w, http.StatusConflict, "token already bound to a different agent_id")
			return
		}
		tokenID = rec.ID
		agent, created, err = a.reg.RegisterPresented(req.AgentID, tokenID, protocol.RoleEdge, req)
		if err == nil && created {
			if berr := a.tokens.BindAgentID(tokenID, agent.ID); berr != nil {
				writeErr(w, http.StatusInternalServerError, "failed to bind agent id")
				return
			}
		}
	}

	if err != nil {
		switch {
		case errors.Is(err, ErrCenterExists):
			writeErr(w, http.StatusConflict, "center already claimed for this hub_id")
		case errors.Is(err, ErrAgentIDCollision):
			writeErr(w, http.StatusConflict, "agent_id collision")
		case errors.Is(err, ErrPublicKeyUsed):
			writeErr(w, http.StatusConflict, err.Error())
		case errors.Is(err, ErrInvalidAgentID), errors.Is(err, ErrInvalidRole):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if created {
		a.log.Info("agent registered", "hub_id", a.cfg.HubID, "agent_id", agent.ID, "role", role, "name", agent.Name, "first", true)
	} else {
		a.log.Info("agent reconnected", "hub_id", a.cfg.HubID, "agent_id", agent.ID, "role", role, "name", agent.Name)
	}
	if a.hub != nil {
		a.hub.persistOrLog()
	}

	nm := a.netmap.ForAgent(agent.ID)
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{
		AgentID:        agent.ID,
		HubID:          a.cfg.HubID,
		Role:           agent.Role,
		CenterAgentID:  a.reg.CenterAgentID(),
		OverlayIP:      agent.OverlayIP.String(),
		DNSName:        agent.DNSName,
		NetmapRevision: nm.Revision,
		Peers:          nm.Peers,
		DNSMap:         nm.DNSMap,
		STUNURLs:       a.cfg.STUNURLs,
		RelayURLs:      a.cfg.RelayURLs,
	})

	if a.hub != nil {
		// Notify counterparties so edges learn center endpoints and vice versa.
		if agent.Role == protocol.RoleCenter {
			a.hub.BroadcastNetmapExcept("")
		} else {
			a.hub.PushNetmapTo(a.reg.CenterAgentID())
		}
	}
}

// ListAgents handles GET /agents.
func (a *API) ListAgents(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireEdgeOrCenterSession(w, r); !ok {
		return
	}
	onlineOnly := r.URL.Query().Get("online") == "true"
	writeJSON(w, http.StatusOK, protocol.AgentsListResponse{
		HubID:         a.cfg.HubID,
		CenterAgentID: a.reg.CenterAgentID(),
		Agents:        a.reg.List(onlineOnly),
	})
}

// GetAgent handles GET /agents/{id}.
func (a *API) GetAgent(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.requireEdgeOrCenterSession(w, r); !ok {
		return
	}
	id := chi.URLParam(r, "id")
	agent, err := a.reg.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, protocol.AgentSummary{
		ID:           agent.ID,
		Name:         agent.Name,
		Role:         agent.Role,
		OverlayIP:    agent.OverlayIP.Addr().String(),
		DNSName:      agent.DNSName,
		Tags:         agent.Tags,
		Capabilities: agent.Capabilities,
		Online:       agent.Online,
		LastSeen:     agent.LastSeen,
	})
}

// GetNetmap handles GET /netmap.
func (a *API) GetNetmap(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := a.requireEdgeOrCenterSession(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.netmap.ForAgent(agentID))
}
