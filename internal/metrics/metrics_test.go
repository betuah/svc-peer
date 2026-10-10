package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCounterAndGaugeExposition(t *testing.T) {
	reg := NewRegistry()
	c := reg.Counter("svc_peer_test_total", "test counter")
	c.Inc("result", "ok")
	c.Add(2, "result", "error")
	g := reg.Gauge("svc_peer_test_gauge", "test gauge")
	g.Set(3, "hub_id", "h1")

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content-type=%q", ct)
	}
	for _, want := range []string{
		"# TYPE svc_peer_test_total counter",
		`svc_peer_test_total{result="ok"} 1`,
		`svc_peer_test_total{result="error"} 2`,
		"# TYPE svc_peer_test_gauge gauge",
		`svc_peer_test_gauge{hub_id="h1"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestHistogramBuckets(t *testing.T) {
	reg := NewRegistry()
	h := reg.Histogram("svc_peer_test_duration_seconds", "latency", []float64{0.1, 0.5})
	h.Observe(0.05, "path", "/health")
	h.Observe(0.2, "path", "/health")

	var b strings.Builder
	if err := reg.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	body := b.String()
	if !strings.Contains(body, `le="0.1"`) || !strings.Contains(body, `path="/health"`) {
		t.Fatalf("bucket labels missing:\n%s", body)
	}
	if !strings.Contains(body, `le="+Inf"`) {
		t.Fatalf("missing +Inf:\n%s", body)
	}
	if !strings.Contains(body, `_count`) || !strings.Contains(body, `_sum`) {
		t.Fatalf("missing sum/count:\n%s", body)
	}
}

func TestCollector(t *testing.T) {
	reg := NewRegistry()
	reg.AddCollector(func(w io.Writer) error {
		return WriteGaugeFamily(w, "svc_peer_live", "live", 7)
	})
	var b strings.Builder
	if err := reg.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "svc_peer_live 7") {
		t.Fatalf("collector missing: %s", b.String())
	}
}
