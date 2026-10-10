package hub

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	h, err := New(Config{
		ListenAddr:      ":0",
		HubID:           "hub-main",
		CenterBootstrap: "boot",
		RelaySecret:     "relay",
		OverlayCIDR:     "10.10.0.0/16",
		LogLevel:        "info",
		LogFormat:       "text",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.Router().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"svc_peer_hub_agents_registered",
		"svc_peer_hub_agents_online",
		"svc_peer_hub_allowlist_size",
		"svc_peer_hub_grants",
		"svc_peer_hub_ws_connections",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in:\n%s", want, body)
		}
	}
}
