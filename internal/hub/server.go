package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Router builds the chi router for the hub.
func (h *Hub) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	api := h.api
	r.Get("/health", api.Health)

	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(60 * time.Second))
		r.Route("/api/v1", func(r chi.Router) {
			r.Post("/agents/register", api.Register)
			r.Get("/agents", api.ListAgents)
			r.Get("/agents/{id}", api.GetAgent)
			r.Get("/netmap", api.GetNetmap)
		})
		// Center → hub allowlist sync (primary edge token path)
		r.Put("/hub/allowlist", api.SyncAllowlist)
		// Break-glass ops (management); revoke also accepts center_bootstrap
		r.Post("/hub/tokens", api.CreateToken)
		r.Delete("/hub/tokens/{id}", api.RevokeToken)
		r.Post("/hub/tokens/{id}/rotate", api.RotateToken)
		r.Post("/hub/grants", api.CreateGrant)
		r.Get("/hub/grants", api.ListGrants)
		r.Delete("/hub/grants/{id}", api.RevokeGrant)
	})

	r.Get("/ws/v1/agent", h.HandleAgentWS)
	return r
}

// ListenAndServe starts the HTTP or HTTPS server until ctx is cancelled.
// When tls_cert_file and tls_key_file are set, serves HTTPS (WebSocket upgrades are WSS).
func (h *Hub) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              h.cfg.ListenAddr,
		Handler:           h.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	tlsEnabled := h.cfg.TLSEnabled()
	if tlsEnabled {
		// Prefer HTTP/1.1 so control WebSocket upgrades work over TLS (WSS).
		// Go's default ListenAndServeTLS enables HTTP/2 via ALPN, which breaks upgrades.
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		}
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	stop := make(chan struct{})
	go h.StartPresenceSweeper(stop)

	errCh := make(chan error, 1)
	go func() {
		h.log.Info("hub listening",
			"addr", h.cfg.ListenAddr,
			"hub_id", h.cfg.HubID,
			"overlay_cidr", h.cfg.OverlayCIDR,
			"role", "nat-bridge",
			"tls", tlsEnabled,
		)
		var err error
		if tlsEnabled {
			err = srv.ListenAndServeTLS(h.cfg.TLSCertFile, h.cfg.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		close(stop)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		close(stop)
		if err != nil {
			return fmt.Errorf("hub serve: %w", err)
		}
		return nil
	}
}
