// Package metrics provides a minimal Prometheus text exposition without
// pulling in client_golang. Scrapes stay cheap: counters/gauges are O(1)
// updates; collectors run only on GET /metrics.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds named metrics and optional scrape-time collectors.
type Registry struct {
	mu         sync.Mutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	collectors []Collector
}

// Collector appends Prometheus text lines at scrape time (gauges derived from live state).
type Collector func(w io.Writer) error

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
	}
}

// AddCollector registers a scrape-time collector.
func (r *Registry) AddCollector(c Collector) {
	if c == nil {
		return
	}
	r.mu.Lock()
	r.collectors = append(r.collectors, c)
	r.mu.Unlock()
}

// Counter returns (or creates) a counter with the given name and help.
func (r *Registry) Counter(name, help string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &Counter{name: name, help: help, children: make(map[string]*labeledCounter)}
	r.counters[name] = c
	return c
}

// Gauge returns (or creates) a gauge with the given name and help.
func (r *Registry) Gauge(name, help string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g := &Gauge{name: name, help: help, children: make(map[string]*labeledGauge)}
	r.gauges[name] = g
	return g
}

// Histogram returns (or creates) a histogram with fixed buckets (seconds).
func (r *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	if len(buckets) == 0 {
		buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	}
	h := &Histogram{name: name, help: help, buckets: append([]float64(nil), buckets...), children: make(map[string]*labeledHistogram)}
	r.histograms[name] = h
	return h
}

// WritePrometheus writes the full exposition to w.
func (r *Registry) WritePrometheus(w io.Writer) error {
	r.mu.Lock()
	counterNames := sortedKeys(r.counters)
	gaugeNames := sortedKeys(r.gauges)
	histNames := sortedKeys(r.histograms)
	collectors := append([]Collector(nil), r.collectors...)
	r.mu.Unlock()

	for _, name := range counterNames {
		r.mu.Lock()
		c := r.counters[name]
		r.mu.Unlock()
		if err := c.write(w); err != nil {
			return err
		}
	}
	for _, name := range gaugeNames {
		r.mu.Lock()
		g := r.gauges[name]
		r.mu.Unlock()
		if err := g.write(w); err != nil {
			return err
		}
	}
	for _, name := range histNames {
		r.mu.Lock()
		h := r.histograms[name]
		r.mu.Unlock()
		if err := h.write(w); err != nil {
			return err
		}
	}
	for _, c := range collectors {
		if err := c(w); err != nil {
			return err
		}
	}
	return nil
}

// Handler serves GET /metrics in Prometheus text format 0.0.4.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if req.Method == http.MethodHead {
			return
		}
		_ = r.WritePrometheus(w)
	})
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Counter is a Prometheus counter (monotonically increasing).
type Counter struct {
	name     string
	help     string
	mu       sync.Mutex
	children map[string]*labeledCounter
}

type labeledCounter struct {
	labels string
	v      atomic.Uint64
}

// Inc increments the counter for the given label set (even number of key,value pairs).
func (c *Counter) Inc(labelPairs ...string) {
	c.add(1, labelPairs...)
}

// Add adds n to the counter.
func (c *Counter) Add(n uint64, labelPairs ...string) {
	c.add(n, labelPairs...)
}

func (c *Counter) add(n uint64, labelPairs ...string) {
	key, labels := encodeLabels(labelPairs...)
	c.mu.Lock()
	child, ok := c.children[key]
	if !ok {
		child = &labeledCounter{labels: labels}
		c.children[key] = child
	}
	c.mu.Unlock()
	child.v.Add(n)
}

func (c *Counter) write(w io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name); err != nil {
		return err
	}
	keys := sortedKeys(c.children)
	for _, k := range keys {
		child := c.children[k]
		if child.labels == "" {
			if _, err := fmt.Fprintf(w, "%s %d\n", c.name, child.v.Load()); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s{%s} %d\n", c.name, child.labels, child.v.Load()); err != nil {
			return err
		}
	}
	return nil
}

// Gauge is a Prometheus gauge.
type Gauge struct {
	name     string
	help     string
	mu       sync.Mutex
	children map[string]*labeledGauge
}

type labeledGauge struct {
	labels string
	f      atomic.Uint64 // float64 bits
}

// Set sets the gauge to v.
func (g *Gauge) Set(v float64, labelPairs ...string) {
	key, labels := encodeLabels(labelPairs...)
	g.mu.Lock()
	child, ok := g.children[key]
	if !ok {
		child = &labeledGauge{labels: labels}
		g.children[key] = child
	}
	g.mu.Unlock()
	child.f.Store(floatBits(v))
}

func (g *Gauge) write(w io.Writer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name); err != nil {
		return err
	}
	keys := sortedKeys(g.children)
	for _, k := range keys {
		child := g.children[k]
		val := floatFromBits(child.f.Load())
		if child.labels == "" {
			if _, err := fmt.Fprintf(w, "%s %s\n", g.name, formatFloat(val)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%s{%s} %s\n", g.name, child.labels, formatFloat(val)); err != nil {
			return err
		}
	}
	return nil
}

// Histogram is a Prometheus histogram with fixed buckets.
type Histogram struct {
	name     string
	help     string
	buckets  []float64
	mu       sync.Mutex
	children map[string]*labeledHistogram
}

type labeledHistogram struct {
	labels string
	counts []atomic.Uint64 // len = len(buckets)+1 (+Inf)
	sumMu  sync.Mutex
	sumF   float64
	count  atomic.Uint64
}

// Observe records one observation (typically seconds).
func (h *Histogram) Observe(v float64, labelPairs ...string) {
	key, labels := encodeLabels(labelPairs...)
	h.mu.Lock()
	child, ok := h.children[key]
	if !ok {
		child = &labeledHistogram{
			labels: labels,
			counts: make([]atomic.Uint64, len(h.buckets)+1),
		}
		h.children[key] = child
	}
	h.mu.Unlock()

	idx := len(h.buckets)
	for i, b := range h.buckets {
		if v <= b {
			idx = i
			break
		}
	}
	// Cumulative: increment this bucket and all higher including +Inf.
	for i := idx; i < len(child.counts); i++ {
		child.counts[i].Add(1)
	}
	child.count.Add(1)
	child.sumMu.Lock()
	child.sumF += v
	child.sumMu.Unlock()
}

func (h *Histogram) write(w io.Writer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name); err != nil {
		return err
	}
	keys := sortedKeys(h.children)
	for _, k := range keys {
		child := h.children[k]
		base := child.labels
		for i, b := range h.buckets {
			le := strconv.FormatFloat(b, 'f', -1, 64)
			lbl := joinLabels(base, `le="`+le+`"`)
			if _, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n", h.name, lbl, child.counts[i].Load()); err != nil {
				return err
			}
		}
		lblInf := joinLabels(base, `le="+Inf"`)
		if _, err := fmt.Fprintf(w, "%s_bucket{%s} %d\n", h.name, lblInf, child.counts[len(h.buckets)].Load()); err != nil {
			return err
		}
		child.sumMu.Lock()
		sum := child.sumF
		child.sumMu.Unlock()
		if base == "" {
			if _, err := fmt.Fprintf(w, "%s_sum %s\n%s_count %d\n", h.name, formatFloat(sum), h.name, child.count.Load()); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "%s_sum{%s} %s\n%s_count{%s} %d\n", h.name, base, formatFloat(sum), h.name, base, child.count.Load()); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinLabels(base, extra string) string {
	if base == "" {
		return extra
	}
	return base + "," + extra
}

func encodeLabels(pairs ...string) (key, labels string) {
	if len(pairs) == 0 {
		return "", ""
	}
	if len(pairs)%2 != 0 {
		pairs = append(pairs, "")
	}
	type kv struct{ k, v string }
	list := make([]kv, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		list = append(list, kv{pairs[i], pairs[i+1]})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].k < list[j].k })
	var b strings.Builder
	var keyB strings.Builder
	for i, p := range list {
		if i > 0 {
			b.WriteByte(',')
			keyB.WriteByte(',')
		}
		esc := escapeLabel(p.v)
		fmt.Fprintf(&b, `%s="%s"`, p.k, esc)
		keyB.WriteString(p.k)
		keyB.WriteByte('=')
		keyB.WriteString(esc)
	}
	return keyB.String(), b.String()
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func floatBits(f float64) uint64 {
	return uint64FromFloat(f)
}

func floatFromBits(u uint64) float64 {
	return floatFromUint64(u)
}

// WriteGaugeFamily writes HELP/TYPE and one gauge sample (for scrape collectors).
func WriteGaugeFamily(w io.Writer, name, help string, value float64, labelPairs ...string) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name); err != nil {
		return err
	}
	_, labels := encodeLabels(labelPairs...)
	if labels == "" {
		_, err := fmt.Fprintf(w, "%s %s\n", name, formatFloat(value))
		return err
	}
	_, err := fmt.Fprintf(w, "%s{%s} %s\n", name, labels, formatFloat(value))
	return err
}

// WriteGaugeSample writes one gauge sample without HELP/TYPE (additional labels).
func WriteGaugeSample(w io.Writer, name string, value float64, labelPairs ...string) error {
	_, labels := encodeLabels(labelPairs...)
	if labels == "" {
		_, err := fmt.Fprintf(w, "%s %s\n", name, formatFloat(value))
		return err
	}
	_, err := fmt.Fprintf(w, "%s{%s} %s\n", name, labels, formatFloat(value))
	return err
}

// WriteCounterFamily writes HELP/TYPE and one counter sample.
func WriteCounterFamily(w io.Writer, name, help string, value uint64, labelPairs ...string) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name); err != nil {
		return err
	}
	_, labels := encodeLabels(labelPairs...)
	if labels == "" {
		_, err := fmt.Fprintf(w, "%s %d\n", name, value)
		return err
	}
	_, err := fmt.Fprintf(w, "%s{%s} %d\n", name, labels, value)
	return err
}

// WriteCounterSample writes one counter sample without HELP/TYPE.
func WriteCounterSample(w io.Writer, name string, value uint64, labelPairs ...string) error {
	_, labels := encodeLabels(labelPairs...)
	if labels == "" {
		_, err := fmt.Fprintf(w, "%s %d\n", name, value)
		return err
	}
	_, err := fmt.Fprintf(w, "%s{%s} %d\n", name, labels, value)
	return err
}
