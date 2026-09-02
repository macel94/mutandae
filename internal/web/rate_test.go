package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterTokenBucket(t *testing.T) {
	fixed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	now := fixed
	rl := newRateLimiter(2, 4, 10, func() time.Time { return now })

	// Burst allows 4 immediate tokens.
	for i := 0; i < 4; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("fifth token should be denied when burst exhausted")
	}
	// Tokens refill at the configured rate.
	now = now.Add(2 * time.Second) // +4 tokens
	if !rl.allow("1.2.3.4") {
		t.Fatal("refilled token should be allowed")
	}
	// A different client has an independent bucket.
	if !rl.allow("5.6.7.8") {
		t.Fatal("unrelated client should have its own allowance")
	}
}

func TestRateLimiterClientIsolation(t *testing.T) {
	rl := newRateLimiter(1, 1, 10, time.Now)
	if !rl.allow("10.0.0.1") {
		t.Fatal("client A first request should pass")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("client A second request should be denied (burst 1)")
	}
	if !rl.allow("10.0.0.2") {
		t.Fatal("client B should be unaffected by client A")
	}
}

func TestThrottleReturns429WhenExceeded(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	reads := newRateLimiter(1000, 1000, 10, func() time.Time { return now })
	writes := newRateLimiter(1, 1, 10, func() time.Time { return now })
	creates := newRateLimiter(1, 1, 10, func() time.Time { return now })
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := throttle(reads, writes, creates, inner)

	// Write burst of 1: first passes, second is throttled.
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/identities/x/rotate", nil)
	r1.RemoteAddr = "10.0.0.1:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first write status = %d, want 200", w1.Code)
	}

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/identities/x/retire", nil)
	r2.RemoteAddr = "10.0.0.1:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second write status = %d, want 429", w2.Code)
	}

	// Reads use the read limiter (burst 1000) so they keep passing.
	r3 := httptest.NewRequest(http.MethodGet, "/api/v1/identities", nil)
	r3.RemoteAddr = "10.0.0.1:1234"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("read after throttled write status = %d, want 200", w3.Code)
	}
}

func TestProvisionRequestClassification(t *testing.T) {
	prov := httptest.NewRequest(http.MethodPost, "/api/v1/demo/identities", nil)
	if !isProvisionRequest(prov) {
		t.Fatal("POST /api/v1/demo/identities should be a provisioning request")
	}
	other := httptest.NewRequest(http.MethodPost, "/api/v1/identities", nil)
	if isProvisionRequest(other) {
		t.Fatal("POST /api/v1/identities should not be classified as provisioning")
	}
	get := httptest.NewRequest(http.MethodGet, "/api/v1/demo/identities", nil)
	if isProvisionRequest(get) {
		t.Fatal("GET should not be classified as provisioning")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want first forwarded hop", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := clientIP(r); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want remote addr", got)
	}
}
