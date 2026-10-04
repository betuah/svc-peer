// Package localapi serves loopback HTTP endpoints on the svc-peer agent process
// (role=center or role=edge). TX/RX come from the local WireGuard device, not the hub.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/betuah/svc-peer/internal/agent/allowlist"
	"github.com/betuah/svc-peer/internal/agent/wgdev"
	"github.com/betuah/svc-peer/internal/protocol"
	"github.com/go-chi/chi/v5"
)

const txRXSource = "wireguard_device"

// View is the agent-facing snapshot the local API needs.
type View interface {
	Role() string
	AgentID() string
	HubID() string
	Name() string
	OverlayIP() string
	CenterAgentID() string
	HubConnected() bool
	WGBackend() string
	// NetmapPeers returns peers currently applied from the ACL netmap.
	NetmapPeers() (peers []protocol.PeerConfig, paths map[string]string)
	// ListHubAgents returns hub registry membership (joined agents + online) when available.
	ListHubAgents(ctx context.Context) (*protocol.AgentsListResponse, error)
	// PeerDeviceStats returns WireGuard device TX/RX/handshake for a peer public key.
	PeerDeviceStats(publicKey string) (wgdev.PeerStats, bool, error)
}

// AllowlistManager is center-only join-token management backed by durable local state.
type AllowlistManager interface {
	ListAllowlist() ([]AllowlistEntryView, error)
	CreateAllowlistEntry(req CreateAllowlistRequest) (AllowlistEntryView, error)
	RevokeAllowlistEntry(id string) (AllowlistEntryView, error)
	SyncAllowlist(ctx context.Context) (AllowlistSyncResult, error)
}

// Server is the agent-local HTTP API.
type Server struct {
	view      View
	allowlist AllowlistManager
	log       *slog.Logger
	srv       *http.Server
}

// New constructs a local API server (not yet listening).
// allowlist may be nil; center allowlist routes then return 503.
func New(view View, allowlist AllowlistManager, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{view: view, allowlist: allowlist, log: log}
	r := chi.NewRouter()
	r.Get("/local/health", s.handleHealth)
	r.Get("/local/status", s.handleStatus)
	r.Get("/local/peers", s.handlePeers)
	r.Get("/local/peers/{id}", s.handlePeerDetail)
	r.Get("/local/allowlist", s.handleAllowlistList)
	r.Post("/local/allowlist", s.handleAllowlistCreate)
	r.Delete("/local/allowlist/{id}", s.handleAllowlistRevoke)
	r.Post("/local/allowlist/sync", s.handleAllowlistSync)
	s.srv = &http.Server{Handler: r}
	return s
}

// Handler exposes the HTTP handler for tests.
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Start binds listenAddr and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return fmt.Errorf("local api listen addr empty")
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("local api listen %s: %w", listenAddr, err)
	}
	s.srv.Addr = listenAddr
	s.log.Info("local api listening", "addr", ln.Addr().String())
	errCh := make(chan error, 1)
	go func() {
		err := s.srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shCtx)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Role:    s.view.Role(),
		AgentID: s.view.AgentID(),
		HubID:   s.view.HubID(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	conn, label := s.centerConnectivity()
	writeJSON(w, http.StatusOK, StatusResponse{
		Role:               s.view.Role(),
		AgentID:            s.view.AgentID(),
		HubID:              s.view.HubID(),
		Name:               s.view.Name(),
		OverlayIP:          s.view.OverlayIP(),
		CenterAgentID:      s.view.CenterAgentID(),
		HubConnected:       s.view.HubConnected(),
		CenterConnected:    conn,
		CenterConnectivity: label,
		WGBackend:          s.view.WGBackend(),
	})
}

func (s *Server) centerConnectivity() (connected bool, label string) {
	role := s.view.Role()
	if role == protocol.RoleCenter {
		return true, "n/a"
	}
	centerID := s.view.CenterAgentID()
	peers, _ := s.view.NetmapPeers()
	for _, p := range peers {
		id := peerID(p)
		if centerID != "" && id != centerID && p.Role != protocol.RoleCenter {
			continue
		}
		if centerID == "" && p.Role != protocol.RoleCenter {
			continue
		}
		if p.PublicKey == "" {
			continue
		}
		st, ok, err := s.view.PeerDeviceStats(p.PublicKey)
		if err != nil || !ok {
			return false, "offline"
		}
		if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 3*time.Minute {
			return true, "online"
		}
		return false, "offline"
	}
	if s.view.HubConnected() {
		return false, "offline"
	}
	return false, "offline"
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.buildPeers(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, PeersResponse{
		Role:  s.view.Role(),
		HubID: s.view.HubID(),
		Peers: peers,
	})
}

func (s *Server) handlePeerDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "peer id required")
		return
	}
	peers, err := s.buildPeers(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	for _, p := range peers {
		if p.ID == id {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "peer not found")
}

func (s *Server) requireCenterAllowlist(w http.ResponseWriter) bool {
	if s.view.Role() != protocol.RoleCenter {
		writeErr(w, http.StatusForbidden, "allowlist management is center-only")
		return false
	}
	if s.allowlist == nil {
		writeErr(w, http.StatusServiceUnavailable, "allowlist store unavailable")
		return false
	}
	return true
}

func (s *Server) handleAllowlistList(w http.ResponseWriter, _ *http.Request) {
	if !s.requireCenterAllowlist(w) {
		return
	}
	entries, err := s.allowlist.ListAllowlist()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []AllowlistEntryView{}
	}
	writeJSON(w, http.StatusOK, AllowlistResponse{Entries: entries})
}

func (s *Server) handleAllowlistCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireCenterAllowlist(w) {
		return
	}
	var req CreateAllowlistRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
	}
	entry, err := s.allowlist.CreateAllowlistEntry(req)
	if err != nil {
		if errors.Is(err, allowlist.ErrAlreadyExists) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Best-effort hub sync after local persist.
	if _, syncErr := s.allowlist.SyncAllowlist(r.Context()); syncErr != nil {
		s.log.Warn("allowlist create persisted; hub sync failed", "id", entry.ID, "err", syncErr)
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleAllowlistRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireCenterAllowlist(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id required")
		return
	}
	entry, err := s.allowlist.RevokeAllowlistEntry(id)
	if err != nil {
		if errors.Is(err, allowlist.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "token not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, syncErr := s.allowlist.SyncAllowlist(r.Context()); syncErr != nil {
		s.log.Warn("allowlist revoke persisted; hub sync failed", "id", id, "err", syncErr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": entry.ID})
}

func (s *Server) handleAllowlistSync(w http.ResponseWriter, r *http.Request) {
	if !s.requireCenterAllowlist(w) {
		return
	}
	res, err := s.allowlist.SyncAllowlist(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) buildPeers(ctx context.Context) ([]PeerView, error) {
	netPeers, paths := s.view.NetmapPeers()
	byID := make(map[string]protocol.PeerConfig, len(netPeers))
	for _, p := range netPeers {
		byID[peerID(p)] = p
	}

	role := s.view.Role()
	selfID := s.view.AgentID()

	// Center: prefer hub registry (edges that have joined) + enrich with netmap/WG stats.
	if role == protocol.RoleCenter {
		list, err := s.view.ListHubAgents(ctx)
		if err != nil {
			// Fall back to netmap-only view if hub is unreachable.
			s.log.Debug("local api hub agents unavailable; using netmap", "err", err)
			return s.peersFromNetmap(netPeers, paths, selfID), nil
		}
		out := make([]PeerView, 0, len(list.Agents))
		for _, a := range list.Agents {
			if a.ID == selfID || a.Role == protocol.RoleCenter {
				continue
			}
			online := a.Online
			lastSeen := a.LastSeen
			pv := PeerView{
				ID:         a.ID,
				Name:       a.Name,
				Role:       a.Role,
				OverlayIP:  a.OverlayIP,
				Online:     &online,
				LastSeen:   &lastSeen,
				TXRXSource: txRXSource,
			}
			if np, ok := byID[a.ID]; ok {
				pv.DNSName = np.DNSName
				pv.PublicKey = np.PublicKey
				pv.Path = paths[a.ID]
				if np.Endpoint != "" {
					pv.Endpoint = np.Endpoint
					pv.EndpointSummary = summarizeEndpoint(np.Endpoint)
				}
				s.applyDeviceStats(&pv, np.PublicKey)
			}
			out = append(out, pv)
		}
		return out, nil
	}

	// Edge: typically center (+ any granted peers) from netmap + WG TX/RX.
	return s.peersFromNetmap(netPeers, paths, selfID), nil
}

func (s *Server) peersFromNetmap(netPeers []protocol.PeerConfig, paths map[string]string, selfID string) []PeerView {
	out := make([]PeerView, 0, len(netPeers))
	for _, p := range netPeers {
		id := peerID(p)
		if id == "" || id == selfID {
			continue
		}
		pv := PeerView{
			ID:         id,
			Role:       p.Role,
			DNSName:    p.DNSName,
			PublicKey:  p.PublicKey,
			Path:       paths[id],
			TXRXSource: txRXSource,
		}
		if len(p.AllowedIPs) > 0 {
			// AllowedIPs are typically "10.x.x.x/32"
			if i := strings.IndexByte(p.AllowedIPs[0], '/'); i >= 0 {
				pv.OverlayIP = p.AllowedIPs[0][:i]
			} else {
				pv.OverlayIP = p.AllowedIPs[0]
			}
		}
		if p.Endpoint != "" {
			pv.Endpoint = p.Endpoint
			pv.EndpointSummary = summarizeEndpoint(p.Endpoint)
		}
		s.applyDeviceStats(&pv, p.PublicKey)
		// Derive online from recent handshake when hub presence is unavailable.
		if !isZeroTime(pv.LastHandshake) && time.Since(*pv.LastHandshake) < 3*time.Minute {
			online := true
			pv.Online = &online
		} else if p.PublicKey != "" {
			online := false
			pv.Online = &online
		}
		out = append(out, pv)
	}
	return out
}

func (s *Server) applyDeviceStats(pv *PeerView, publicKey string) {
	if publicKey == "" {
		return
	}
	st, ok, err := s.view.PeerDeviceStats(publicKey)
	if err != nil || !ok {
		return
	}
	pv.TXBytes = st.TransmitBytes
	pv.RXBytes = st.ReceiveBytes
	if st.Endpoint != "" {
		pv.Endpoint = st.Endpoint
		pv.EndpointSummary = summarizeEndpoint(st.Endpoint)
	}
	if !st.LastHandshake.IsZero() {
		hs := st.LastHandshake.UTC()
		pv.LastHandshake = &hs
	}
}

func peerID(p protocol.PeerConfig) string {
	if p.PeerID != "" {
		return p.PeerID
	}
	return p.AgentID
}

func summarizeEndpoint(ep string) string {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return ep
	}
	return host + ":" + port
}

func isZeroTime(t *time.Time) bool {
	return t == nil || t.IsZero()
}
