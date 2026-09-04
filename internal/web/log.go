package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// structuredLogger keeps the existing small Logger boundary while emitting
// one JSON object per line. The wrapped logger remains responsible for the
// actual destination, flags, and synchronization (log.Logger is safe for
// concurrent use).
type structuredLogger struct {
	base Logger
	now  Clock
}

func newStructuredLogger(base Logger, now Clock) *structuredLogger {
	return &structuredLogger{base: base, now: now}
}

func (l *structuredLogger) Printf(format string, args ...any) {
	l.Log("info", fmt.Sprintf(format, args...))
}

func (l *structuredLogger) Log(level, message string, keyValues ...any) {
	if l == nil || l.base == nil {
		return
	}
	record := make(map[string]any, 3+len(keyValues)/2)
	at := time.Now().UTC()
	if l.now != nil {
		at = l.now().UTC()
	}
	record["ts"] = at.Format(time.RFC3339Nano)
	record["level"] = level
	record["msg"] = message
	for i := 0; i < len(keyValues); i += 2 {
		key := fmt.Sprintf("arg_%d", i/2)
		if value, ok := keyValues[i].(string); ok && value != "" {
			key = value
		}
		var value any = ""
		if i+1 < len(keyValues) {
			value = keyValues[i+1]
		}
		record[key] = value
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		// The logger must never panic on an application request. All ordinary
		// key/value values are JSON-safe; this fallback also handles an
		// accidentally supplied unsupported value.
		encoded = []byte(fmt.Sprintf(`{"ts":%q,"level":%q,"msg":%q}`, record["ts"], level, message))
	}
	l.base.Printf("%s", encoded)
}

// RequestIDFromContext returns the validated inbound or generated request ID.
func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

type requestIDContextKey struct{}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-Id")
		if !validRequestID(requestID) {
			requestID = generatedRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
		// A downstream handler may replace headers before writing, so make the
		// echo explicit after it returns as well.
		w.Header().Set("X-Request-Id", requestID)
	})
}

func validRequestID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func generatedRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}
	// crypto/rand failure is exceptionally unusual, but request handling must
	// still be total. Hashing process-local time gives a printable bounded ID;
	// it is not used as a security credential.
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return hex.EncodeToString(hash[:16])
}

func requestLogMiddleware(logger *structuredLogger, now Clock, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		if now != nil {
			started = now()
		}
		capture := &responseCapture{ResponseWriter: w}
		next.ServeHTTP(capture, r)
		finished := time.Now()
		if now != nil {
			finished = now()
		}
		if logger != nil {
			logger.Log("info", "http request",
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", capture.statusCode(),
				"duration_seconds", finished.Sub(started).Seconds(),
			)
		}
	})
}

func recoveryMiddleware(logger *structuredLogger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if logger != nil {
					logger.Log("error", "http panic recovered",
						"request_id", RequestIDFromContext(r.Context()),
						"method", r.Method,
						"path", r.URL.Path,
						"panic", fmt.Sprint(recovered),
					)
				}
				writeRecoveryResponse(w, r)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeRecoveryResponse(w http.ResponseWriter, r *http.Request) {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") || strings.Contains(accept, "application/vnd.mutandae") || strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"internal server error"}}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><title>Internal Server Error</title><h1>Internal Server Error</h1></html>\n"))
}
