package web

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/internal/buildinfo"
)

// MetricsConfig reserves a dependency-injection seam for deployment-specific
// observability settings. Metrics are always registered and served; Enabled is
// retained for callers that want to make the intent explicit.
type MetricsConfig struct {
	Enabled bool
}

// Metrics is a small, instance-owned Prometheus registry. It intentionally
// exposes only the hooks needed by future packages rather than a global
// registry, keeping tests isolated and avoiding hidden mutable state.
type Metrics struct {
	mu         sync.Mutex
	now        Clock
	startedAt  time.Time
	counters   map[string]metricSeries
	histograms map[string]*histogramSeries
	build      buildinfo.Build
}

type metricSeries struct {
	name   string
	labels map[string]string
	value  float64
}

type histogramSeries struct {
	name    string
	labels  map[string]string
	buckets [len(metricBuckets)]uint64
	count   uint64
	sum     float64
}

var metricBuckets = [...]float64{0.005, 0.025, 0.1, 0.25, 1, 5}

func newMetrics(now Clock) *Metrics {
	startedAt := time.Now().UTC()
	if now != nil {
		startedAt = now().UTC()
	}
	return &Metrics{
		now:        now,
		startedAt:  startedAt,
		counters:   make(map[string]metricSeries),
		histograms: make(map[string]*histogramSeries),
		build:      buildinfo.Current(),
	}
}

// MetricsFromContext retrieves the request-local registry. It is safe for
// packages that do not know whether the web layer installed observability.
func MetricsFromContext(ctx context.Context) *Metrics {
	metrics, _ := ctx.Value(metricsContextKey{}).(*Metrics)
	return metrics
}

type metricsContextKey struct{}

// IncCounter records an arbitrary counter series using a copied label set.
func (m *Metrics) IncCounter(name string, labels map[string]string) {
	if m == nil || name == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := seriesKey(name, labels)
	series := m.counters[key]
	if series.name == "" {
		series = metricSeries{name: name, labels: copyLabels(labels)}
	}
	series.value++
	m.counters[key] = series
}

// ObserveDuration records a duration in seconds in the request histogram
// bucket set. Values below zero are clamped because injected test clocks can
// deliberately model a clock correction.
func (m *Metrics) ObserveDuration(name string, seconds float64, labels map[string]string) {
	if m == nil || name == "" {
		return
	}
	if seconds < 0 {
		seconds = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := seriesKey(name, labels)
	series := m.histograms[key]
	if series == nil {
		series = &histogramSeries{name: name, labels: copyLabels(labels)}
		m.histograms[key] = series
	}
	for i, bucket := range metricBuckets {
		if seconds <= bucket {
			series.buckets[i]++
		}
	}
	series.count++
	series.sum += seconds
}

func metricsMiddleware(metrics *Metrics, now Clock, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		if now != nil {
			started = now()
		}
		ctx := context.WithValue(r.Context(), metricsContextKey{}, metrics)
		capture := &responseCapture{ResponseWriter: w}
		// Keep the request pointer stable so the outer middleware can observe
		// ServeMux's Go 1.22 Request.Pattern after dispatch.
		*r = *r.WithContext(ctx)
		next.ServeHTTP(capture, r)
		finished := time.Now()
		if now != nil {
			finished = now()
		}
		if metrics == nil {
			return
		}
		labels := map[string]string{
			"method": r.Method,
			"route":  requestRoute(r),
			"status": strconv.Itoa(capture.statusCode()),
		}
		metrics.IncCounter("http_requests_total", labels)
		metrics.ObserveDuration("http_request_duration_seconds", finished.Sub(started).Seconds(), map[string]string{
			"method": r.Method,
			"route":  requestRoute(r),
		})
	})
}

// responseCapture records the status while preserving the ordinary
// ResponseWriter contract used by handlers. The route is read after ServeMux
// runs, when Request.Pattern has been populated.
type responseCapture struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (w *responseCapture) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseCapture) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *responseCapture) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseCapture) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func requestRoute(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return sanitizeRoute(r.URL.Path)
}

// sanitizeRoute is only the fallback for requests rejected before ServeMux or
// unmatched paths. Registered Go 1.22 patterns are preferred because they
// already express `{id}` placeholders. The fallback replaces identity-like,
// UUID, numeric, and long hexadecimal segments so an attacker cannot create
// unbounded label cardinality or put raw identity IDs into metrics.
func sanitizeRoute(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		segment := parts[i]
		if segment == "" {
			continue
		}
		previous := ""
		if i > 0 {
			previous = parts[i-1]
		}
		// The fallback must remain bounded even for an unmatched URL. Keep a
		// small set of route vocabulary and collapse every other segment; this
		// preserves useful API/UI prefixes while never turning attacker-chosen
		// path text into an unbounded label. Matched Go 1.22 patterns take the
		// normal path above and do not need this vocabulary.
		if previous == "identities" || isNumericSegment(segment) || isHexLikeSegment(segment) || strings.Contains(segment, "{") || !isRouteVocabulary(segment) {
			parts[i] = "{id}"
		}
	}
	cleaned := strings.Join(parts, "/")
	if cleaned == "" {
		return "/"
	}
	return cleaned
}

func isRouteVocabulary(segment string) bool {
	switch segment {
	case "api", "v1", "integration", "requirements", "connect", "session", "applications", "secrets", "read", "invalidate",
		"partials", "identities", "events", "rotate", "retire", "use", "provision", "demo", "configuration", "livez", "readyz", "metrics",
		"auth", "login", "callback", "logout", "static", "favicon.ico", "favicon.svg":
		return true
	default:
		return false
	}
}

func isNumericSegment(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func isHexLikeSegment(value string) bool {
	if len(value) < 12 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f') || (value[i] >= 'A' && value[i] <= 'F') || value[i] == '-') {
			return false
		}
	}
	return true
}

func (m *Metrics) serveHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	counters := make([]metricSeries, 0, len(m.counters))
	for _, series := range m.counters {
		counters = append(counters, metricSeries{name: series.name, labels: copyLabels(series.labels), value: series.value})
	}
	histograms := make([]histogramSeries, 0, len(m.histograms))
	for _, series := range m.histograms {
		copySeries := histogramSeries{name: series.name, labels: copyLabels(series.labels), buckets: series.buckets, count: series.count, sum: series.sum}
		histograms = append(histograms, copySeries)
	}
	m.mu.Unlock()
	sort.Slice(counters, func(i, j int) bool {
		return seriesKey(counters[i].name, counters[i].labels) < seriesKey(counters[j].name, counters[j].labels)
	})
	sort.Slice(histograms, func(i, j int) bool {
		return seriesKey(histograms[i].name, histograms[i].labels) < seriesKey(histograms[j].name, histograms[j].labels)
	})

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	writeMetricLine(w, "# HELP http_requests_total Total HTTP requests handled by route and status", "")
	writeMetricLine(w, "# TYPE http_requests_total counter", "")
	for _, series := range counters {
		writeMetricLine(w, series.name+formatLabels(series.labels), strconv.FormatFloat(series.value, 'f', -1, 64))
	}
	writeMetricLine(w, "# HELP http_request_duration_seconds HTTP request duration in seconds", "")
	writeMetricLine(w, "# TYPE http_request_duration_seconds histogram", "")
	for _, series := range histograms {
		for i, bucket := range metricBuckets {
			labels := copyLabels(series.labels)
			labels["le"] = formatBucket(bucket)
			writeMetricLine(w, series.name+"_bucket"+formatLabels(labels), strconv.FormatUint(series.buckets[i], 10))
		}
		labels := copyLabels(series.labels)
		labels["le"] = "+Inf"
		writeMetricLine(w, series.name+"_bucket"+formatLabels(labels), strconv.FormatUint(series.count, 10))
		writeMetricLine(w, series.name+"_sum"+formatLabels(series.labels), strconv.FormatFloat(series.sum, 'f', -1, 64))
		writeMetricLine(w, series.name+"_count"+formatLabels(series.labels), strconv.FormatUint(series.count, 10))
	}
	writeMetricLine(w, "# HELP go_goroutines Number of goroutines", "")
	writeMetricLine(w, "# TYPE go_goroutines gauge", "")
	writeMetricLine(w, "go_goroutines", strconv.Itoa(runtime.NumGoroutine()))
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	writeMetricLine(w, "# HELP go_memstats_alloc_bytes Bytes of allocated heap objects", "")
	writeMetricLine(w, "# TYPE go_memstats_alloc_bytes gauge", "")
	writeMetricLine(w, "go_memstats_alloc_bytes", strconv.FormatUint(memory.Alloc, 10))
	uptime := time.Since(m.startedAt).Seconds()
	if m.now != nil {
		uptime = m.now().Sub(m.startedAt).Seconds()
	}
	if uptime < 0 {
		uptime = 0
	}
	writeMetricLine(w, "# HELP mutandae_uptime_seconds Process uptime in seconds", "")
	writeMetricLine(w, "# TYPE mutandae_uptime_seconds gauge", "")
	writeMetricLine(w, "mutandae_uptime_seconds", strconv.FormatFloat(uptime, 'f', -1, 64))
	revision := m.build.Revision
	if revision == "" {
		revision = "unknown"
	}
	writeMetricLine(w, "# HELP mutandae_build_info Build revision information", "")
	writeMetricLine(w, "# TYPE mutandae_build_info gauge", "")
	writeMetricLine(w, "mutandae_build_info"+formatLabels(map[string]string{"revision": revision}), "1")
}

func writeMetricLine(w http.ResponseWriter, name, value string) {
	if value == "" {
		_, _ = fmt.Fprintln(w, name)
		return
	}
	_, _ = fmt.Fprintln(w, name, value)
}

func formatBucket(value float64) string {
	return strconv.FormatFloat(value, 'f', -3, 64)
}

func seriesKey(name string, labels map[string]string) string {
	return name + formatLabels(labels)
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(key)
		builder.WriteString("=\"")
		builder.WriteString(strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n").Replace(labels[key]))
		builder.WriteString("\"")
	}
	builder.WriteByte('}')
	return builder.String()
}

func copyLabels(labels map[string]string) map[string]string {
	copy := make(map[string]string, len(labels))
	for key, value := range labels {
		copy[key] = value
	}
	return copy
}
