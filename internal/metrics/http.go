package metrics

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// HTTPMetrics holds request counters and latency histograms for one process.
type HTTPMetrics struct {
	Requests *Counter
	Duration *Histogram
}

// NewHTTPMetrics registers HTTP request metrics on reg with a metric name prefix
// (e.g. "svc_peer_hub_http").
func NewHTTPMetrics(reg *Registry, prefix string) *HTTPMetrics {
	return &HTTPMetrics{
		Requests: reg.Counter(prefix+"_requests_total", "HTTP requests handled"),
		Duration: reg.Histogram(prefix+"_request_duration_seconds", "HTTP request latency in seconds", nil),
	}
}

// Middleware records request counts and latency. Route labels use chi patterns
// when available to keep cardinality low.
func (m *HTTPMetrics) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		path := routePath(r)
		status := strconv.Itoa(ww.Status())
		if status == "0" {
			status = "200"
		}
		m.Requests.Inc("method", r.Method, "path", path, "status", status)
		m.Duration.Observe(time.Since(start).Seconds(), "method", r.Method, "path", path)
	})
}

func routePath(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	if r.URL != nil && r.URL.Path != "" {
		return r.URL.Path
	}
	return "unknown"
}

// RequestLogger logs HTTP requests: Warn on 5xx, Debug otherwise. Includes request_id when set.
func RequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			status := ww.Status()
			if status == 0 {
				status = 200
			}
			attrs := []any{
				"method", r.Method,
				"path", routePath(r),
				"status", status,
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if id := middleware.GetReqID(r.Context()); id != "" {
				attrs = append(attrs, "request_id", id)
			}
			if status >= 500 {
				log.Warn("http request", attrs...)
			} else {
				log.Debug("http request", attrs...)
			}
		})
	}
}
