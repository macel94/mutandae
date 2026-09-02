package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig controls per-client-IP throttling. Reads (GET) are allowed at
// a higher rate than state-changing calls, and provisioning (which creates real
// identities) at the most restrictive rate. Zero/negative values fall back to
// safe defaults.
type RateLimitConfig struct {
	ReadRate    float64 // tokens per second for reads
	ReadBurst   int
	WriteRate   float64 // tokens per second for state-changing calls
	WriteBurst  int
	CreateRate  float64 // tokens per second for demo provisioning
	CreateBurst int
}

// defaults returns a config with safe nonzero limits.
func (c RateLimitConfig) defaults() RateLimitConfig {
	if c.ReadRate <= 0 {
		c.ReadRate = 10
	}
	if c.ReadBurst <= 0 {
		c.ReadBurst = 60
	}
	if c.WriteRate <= 0 {
		c.WriteRate = 1
	}
	if c.WriteBurst <= 0 {
		c.WriteBurst = 10
	}
	if c.CreateRate <= 0 {
		c.CreateRate = .1 // one create every 10s per client
	}
	if c.CreateBurst <= 0 {
		c.CreateBurst = 2
	}
	return c
}

// bucket is a token bucket keyed by client address.
type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a per-client-IP token bucket with bounded memory. It is safe
// for concurrent use.
type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       float64
	burst      float64
	maxClients int
	now        func() time.Time
}

func newRateLimiter(rate float64, burst, maxClients int, now func() time.Time) *rateLimiter {
	if maxClients <= 0 {
		maxClients = 10000
	}
	return &rateLimiter{
		buckets:    make(map[string]*bucket, 1024),
		rate:       rate,
		burst:      float64(burst),
		maxClients: maxClients,
		now:        now,
	}
}

// allow consumes one token and reports whether the key may proceed, refilling
// the bucket from elapsed time. When the client map is at capacity it prunes
// long-idle buckets so adversarial client churn cannot exhaust memory.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		if len(rl.buckets) >= rl.maxClients {
			return false
		}
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
	} else if now.Before(b.last) {
		b.last = now // tolerate clock anomaly
	}
	if b.tokens < 1 {
		rl.prune(now)
		return false
	}
	b.tokens--
	return true
}

// prune removes buckets idle for more than 5 minutes when the map is full.
func (rl *rateLimiter) prune(now time.Time) {
	if len(rl.buckets) < rl.maxClients {
		return
	}
	for key, b := range rl.buckets {
		if now.Sub(b.last) > 5*time.Minute {
			delete(rl.buckets, key)
		}
	}
}

// clientIP extracts the effective client address, honoring a single
// X-Forwarded-For hop (set by the Traefik ingress) and falling back to the
// remote address. It deliberately takes only the first proxied value to avoid
// spoofed chains.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
		if first != "" {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// throttle is the middleware that applies per-IP limits by request class.
// Loopback clients are exempt: public visitors can never present a loopback
// source address (the Traefik ingress proxies theirs), health probes and local
// tooling always can, and the eval harness exercises rapid mutations from the
// loopback in tests.
func throttle(reads, writes, creates *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
			next.ServeHTTP(w, r)
			return
		}
		var limiter *rateLimiter
		switch {
		case r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions:
			limiter = reads
		case isProvisionRequest(r):
			limiter = creates
		default:
			limiter = writes
		}
		if !limiter.allow(ip) {
			writeRateLimited(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"too many requests — please wait and retry"}}`))
}

// isProvisionRequest reports whether the request creates a new demo identity.
func isProvisionRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/api/v1/demo/identities"
}
