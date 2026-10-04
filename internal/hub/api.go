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

// API holds HTTP handlers for the hub control plane.
type API struct {
	cfg     Config
	tokens  *TokenStore
	reg     *Registry
	netmap  *NetmapBuilder
	log     *slog.Logger
	hub     *Hub // for WS push stubs
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

func (a *API) requireHubSecret(w http.ResponseWriter, r *http.Request) bool {
	tok := bearerToken(r)
	if tok == "" || tok != a.cfg.HubSecret {
		writeErr(w, http.StatusUnauthorized, "hub_secret required")
		return false
	}
	return true
}

func (a *API) requireAgentToken(w http.ResponseWriter, r *http.Request) (*TokenRecord, bool) {
	raw := bearerToken(r)
	rec, err := a.tokens.Lookup(raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid agent token")
		return nil, false
	}
	return rec, true
}

// Health handles GET /health.
func (a *API) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.HealthResponse{
		Status:          "ok",
		AgentsConnected: a.reg.OnlineCount(),
		NetmapRevision:  a.reg.Revision(),
	})
}

// CreateToken handles POST /hub/tokens.
func (a *API) CreateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireHubSecret(w, r) {
		return
	}
	var req protocol.CreateTokenRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
	}
	rec, raw, err := a.tokens.Mint(req.Label, req.Tags)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, protocol.TokenInfo{
		ID:        rec.ID,
		Label:     rec.Label,
		Token:     raw,
		AgentID:   rec.AgentID,
		Revoked:   rec.Revoked,
		CreatedAt: rec.CreatedAt,
	})
}

// RevokeToken handles DELETE /hub/tokens/{id}.
func (a *API) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireHubSecret(w, r) {
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// RotateToken handles POST /hub/tokens/{id}/rotate.
func (a *API) RotateToken(w http.ResponseWriter, r *http.Request) {
	if !a.requireHubSecret(w, r) {
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
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.RotateTokenResponse{
		ID:      rec.ID,
		Token:   raw,
		AgentID: rec.AgentID,
	})
}

// Register handles POST /agents/register.
func (a *API) Register(w http.ResponseWriter, r *http.Request) {
	rec, ok := a.requireAgentToken(w, r)
	if !ok {
		return
	}
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	agent, created, err := a.reg.RegisterFirstOrReconnect(rec.ID, rec.AgentID, req)
	if err != nil {
		switch {
		case errors.Is(err, ErrAgentNotFound):
			writeErr(w, http.StatusConflict, "bound agent missing from registry")
		case errors.Is(err, ErrPublicKeyUsed):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if created {
		if err := a.tokens.BindAgentID(rec.ID, agent.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to bind agent id")
			return
		}
		a.log.Info("agent registered", "agent_id", agent.ID, "name", agent.Name, "first", true)
	} else {
		a.log.Info("agent reconnected", "agent_id", agent.ID, "name", agent.Name)
	}

	nm := a.netmap.ForAgent(agent.ID)
	writeJSON(w, http.StatusOK, protocol.RegisterResponse{
		AgentID:        agent.ID,
		OverlayIP:      agent.OverlayIP.String(),
		DNSName:        agent.DNSName,
		NetmapRevision: nm.Revision,
		Peers:          nm.Peers,
		DNSMap:         nm.DNSMap,
		STUNURLs:       a.cfg.STUNURLs,
		RelayURLs:      a.cfg.RelayURLs,
	})

	// Stub: push netmap to peers when membership changes.
	if a.hub != nil {
		a.hub.BroadcastNetmapExcept(agent.ID)
	}
}

// ListAgents handles GET /agents.
func (a *API) ListAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAgentToken(w, r); !ok {
		return
	}
	onlineOnly := r.URL.Query().Get("online") == "true"
	writeJSON(w, http.StatusOK, protocol.AgentsListResponse{
		Agents: a.reg.List(onlineOnly),
	})
}

// GetAgent handles GET /agents/{id}.
func (a *API) GetAgent(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAgentToken(w, r); !ok {
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
	rec, ok := a.requireAgentToken(w, r)
	if !ok {
		return
	}
	if rec.AgentID == "" {
		writeErr(w, http.StatusConflict, "agent not registered yet")
		return
	}
	writeJSON(w, http.StatusOK, a.netmap.ForAgent(rec.AgentID))
}
