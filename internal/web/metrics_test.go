package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsEndpointAndRouteLabels(t *testing.T) {
	current := testNow()
	metrics := newMetrics(func() time.Time { return current })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /identities/{id}", func(w http.ResponseWriter, r *http.Request) {
		if MetricsFromContext(r.Context()) != metrics {
			t.Fatal("MetricsFromContext did not return the request registry")
		}
		MetricsFromContext(r.Context()).IncCounter("mutandae_test_counter", map[string]string{"kind": "test"})
		current = current.Add(125 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	})
	handler := metricsMiddleware(metrics, func() time.Time { return current }, mux)
	request := httptest.NewRequest(http.MethodGet, "/identities/orders-production-secret-1234567890", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("request status = %d, want %d", response.Code, http.StatusCreated)
	}

	metricsResponse := httptest.NewRecorder()
	metrics.serveHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metricsResponse.Code)
	}
	if got := metricsResponse.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("metrics content type = %q", got)
	}
	for _, expected := range []string{
		`# TYPE http_requests_total counter`,
		`http_requests_total{method="GET",route="GET /identities/{id}",status="201"} 1`,
		`# TYPE http_request_duration_seconds histogram`,
		`http_request_duration_seconds_bucket{le="0.005",method="GET",route="GET /identities/{id}"} 0`,
		`http_request_duration_seconds_bucket{le="0.1",method="GET",route="GET /identities/{id}"} 0`,
		`http_request_duration_seconds_bucket{le="0.25",method="GET",route="GET /identities/{id}"} 1`,
		`http_request_duration_seconds_bucket{le="+Inf",method="GET",route="GET /identities/{id}"} 1`,
		`http_request_duration_seconds_count{method="GET",route="GET /identities/{id}"} 1`,
		`mutandae_test_counter{kind="test"} 1`,
		"# TYPE go_goroutines gauge\n",
		`go_goroutines `,
		"# TYPE go_memstats_alloc_bytes gauge\n",
		`go_memstats_alloc_bytes `,
		`mutandae_build_info{revision=`,
		"# TYPE mutandae_uptime_seconds gauge\n",
		`mutandae_uptime_seconds `,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics output does not contain %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "orders-production-secret-1234567890") {
		t.Fatalf("metrics output leaked an identity-like route segment:\n%s", body)
	}
	if !strings.Contains(body, `mutandae_build_info{revision="`) || !strings.Contains(body, " 1\n") {
		t.Fatalf("build info is not in Prometheus name-label-value form:\n%s", body)
	}
}

func TestSanitizeRouteBoundsUnmatchedPaths(t *testing.T) {
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "/identities/customer-42", want: "/identities/{id}"},
		{path: "/unmatched/secret-name", want: "/{id}/{id}"},
		{path: "/api/v1/unknown-resource", want: "/api/v1/{id}"},
	} {
		t.Run(test.path, func(t *testing.T) {
			if got := sanitizeRoute(test.path); got != test.want {
				t.Fatalf("sanitizeRoute(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}
