package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/betuah/svc-peer/internal/metrics"
	"github.com/go-chi/chi/v5"
)

// Server runs UDP + HTTP(WS) relay listeners.
type Server struct {
	cfg   Config
	log   *slog.Logger
	udp   *UDPForwarder
	ws    *WSHub
	met   *metrics.Registry
	stats *relayStats
}

// New creates a relay server.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "relay")
	met := metrics.NewRegistry()
	stats := newRelayStats(met)
	met.AddCollector(stats.collect)

	udp, err := NewUDPForwarder(cfg.UDPListenAddr, cfg.RelaySecret, log, stats)
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}
	return &Server{
		cfg:   cfg,
		log:   log,
		udp:   udp,
		ws:    NewWSHub(cfg.RelaySecret, log, stats),
		met:   met,
		stats: stats,
	}, nil
}

// Metrics returns the Prometheus registry (GET /metrics on the HTTP listen address).
func (s *Server) Metrics() *metrics.Registry { return s.met }

// Run serves UDP forwarder and WS until ctx cancel.
func (s *Server) Run(ctx context.Context) error {
	defer s.udp.Close()

	r := chi.NewRouter()
	r.Use(metrics.RequestLogger(s.log))
	httpMetrics := metrics.NewHTTPMetrics(s.met, "svc_peer_relay_http")
	r.Use(httpMetrics.Middleware)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","role":"relay"}`))
	})
	r.Get("/metrics", s.met.Handler().ServeHTTP)
	r.Get("/relay", s.ws.HandleRelay)

	httpAddr := s.cfg.HTTPListenAddr
	if httpAddr == "" || httpAddr == s.cfg.UDPListenAddr {
		httpAddr = ":3479"
		s.log.Info("relay HTTP/WS using separate port",
			"http", httpAddr, "udp", s.cfg.UDPListenAddr)
	}

	srv := &http.Server{
		Addr:              httpAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		if err := s.udp.Run(ctx); err != nil && err != context.Canceled {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	go func() {
		s.log.Info("relay HTTP/WS listening",
			"addr", httpAddr,
			"udp", s.cfg.UDPListenAddr,
			"log_level", s.cfg.LogLevel,
			"log_format", s.cfg.LogFormat,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return err
	}
}
