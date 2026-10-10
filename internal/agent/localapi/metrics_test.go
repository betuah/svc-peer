package localapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/betuah/svc-peer/internal/metrics"
	"github.com/betuah/svc-peer/internal/protocol"
)

func TestMetricsRoute(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.Counter("svc_peer_agent_register_total", "register").Inc("result", "ok")
	s := New(&fakeView{role: protocol.RoleEdge, agentID: "e1", hubID: "h1"}, nil, nil, nil, reg)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "svc_peer_agent_register_total") {
		t.Fatalf("missing register metric: %s", body)
	}
	if !strings.Contains(body, "svc_peer_agent_local_api_requests_total") &&
		!strings.Contains(body, "# TYPE svc_peer_agent_local_api_requests_total") {
		// counter family is created at New; may appear after first request — hit health then metrics
	}
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/local/health", nil))
	rec3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec3.Body.String(), "svc_peer_agent_local_api_requests_total") {
		t.Fatalf("missing local api request metric:\n%s", rec3.Body.String())
	}
	_ = io.Discard
}
