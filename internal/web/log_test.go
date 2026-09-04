package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type lineLogger struct {
	lines []string
}

func (l *lineLogger) Printf(format string, args ...any) {
	// The structured logger always passes one already-encoded line, but using
	// Sprintf keeps this fake faithful to the Logger contract.
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func TestStructuredLoggerAndRequestID(t *testing.T) {
	clockValue := testNow()
	base := &lineLogger{}
	logger := newStructuredLogger(base, func() time.Time { return clockValue })
	logger.Log("info", "direct message", "answer", 42)
	var direct map[string]any
	if err := json.Unmarshal([]byte(base.lines[0]), &direct); err != nil {
		t.Fatalf("structured log is not JSON: %v", err)
	}
	if direct["ts"] != testNow().Format(time.RFC3339Nano) || direct["level"] != "info" || direct["msg"] != "direct message" || direct["answer"] != float64(42) {
		t.Fatalf("unexpected structured record: %#v", direct)
	}

	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		clockValue = clockValue.Add(250 * time.Millisecond)
		panic("test panic")
	})
	handler := requestIDMiddleware(requestLogMiddleware(logger, func() time.Time { return clockValue }, recoveryMiddleware(logger, panicHandler)))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/panic", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-Id", "request-id-123456")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", response.Code)
	}
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("panic content type = %q, want JSON", response.Header().Get("Content-Type"))
	}
	if response.Header().Get("X-Request-Id") != "request-id-123456" {
		t.Fatalf("request ID echo = %q", response.Header().Get("X-Request-Id"))
	}
	if !strings.Contains(response.Body.String(), `"internal_error"`) {
		t.Fatalf("panic body = %q", response.Body.String())
	}
	if len(base.lines) != 3 {
		t.Fatalf("log line count = %d, want direct + panic + request", len(base.lines))
	}
	foundPanic, foundRequest := false, false
	for _, line := range base.lines[1:] {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if record["request_id"] != "request-id-123456" {
			t.Fatalf("record request_id = %#v", record["request_id"])
		}
		switch record["msg"] {
		case "http panic recovered":
			foundPanic = true
		case "http request":
			foundRequest = true
			if record["status"] != float64(http.StatusInternalServerError) {
				t.Fatalf("request status log = %#v", record["status"])
			}
			if record["duration_seconds"] != 0.25 {
				t.Fatalf("request duration log = %#v, want 0.25", record["duration_seconds"])
			}
		}
	}
	if !foundPanic || !foundRequest {
		t.Fatalf("missing panic/request records in %#v", base.lines)
	}
}

func TestRequestIDGeneratedAndHTMLRecovery(t *testing.T) {
	var observed string
	idHandler := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "too-short")
	response := httptest.NewRecorder()
	idHandler.ServeHTTP(response, req)
	if len(observed) != 32 || !validRequestID(observed) || response.Header().Get("X-Request-Id") != observed {
		t.Fatalf("generated request ID = %q, echoed = %q", observed, response.Header().Get("X-Request-Id"))
	}

	recovery := recoveryMiddleware(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("html panic")
	}))
	htmlRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	htmlResponse := httptest.NewRecorder()
	recovery.ServeHTTP(htmlResponse, htmlRequest)
	if htmlResponse.Code != http.StatusInternalServerError || !strings.HasPrefix(htmlResponse.Header().Get("Content-Type"), "text/html") || !strings.Contains(htmlResponse.Body.String(), "Internal Server Error") {
		t.Fatalf("HTML recovery response = (%d, %q, %q)", htmlResponse.Code, htmlResponse.Header().Get("Content-Type"), htmlResponse.Body.String())
	}
}
