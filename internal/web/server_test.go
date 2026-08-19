package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	server, err := newServer(Dependencies{
		Lifecycle: lifecycle.NewDemoStore(now),
		Clock:     func() time.Time { return now },
		Logger:    testLogger{},
	})
	if err != nil {
		t.Fatalf("newServer() error = %v", err)
	}
	return server
}

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	return testServer(t).routes()
}

type testLogger struct{}

func (testLogger) Printf(string, ...any) {}

type fakeLifecycle struct {
	identities []lifecycle.Identity
	events     map[string][]lifecycle.Event
	rotatedID  string
}

func (f *fakeLifecycle) List() []lifecycle.Identity {
	return append([]lifecycle.Identity(nil), f.identities...)
}

func (f *fakeLifecycle) Get(id string) (lifecycle.Identity, bool) {
	for _, identity := range f.identities {
		if identity.ID == id {
			return identity, true
		}
	}
	return lifecycle.Identity{}, false
}

func (f *fakeLifecycle) Events(id string) ([]lifecycle.Event, bool) {
	events, ok := f.events[id]
	return append([]lifecycle.Event(nil), events...), ok
}

func (f *fakeLifecycle) Rotate(id string, now time.Time) (lifecycle.Identity, error) {
	f.rotatedID = id
	identity, ok := f.Get(id)
	if !ok {
		return lifecycle.Identity{}, lifecycle.ErrNotFound
	}
	identity.LastRotatedAt = now
	return identity, nil
}

func TestNewServerRequiresDependencies(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	valid := Dependencies{
		Lifecycle: lifecycle.NewDemoStore(now),
		Clock:     func() time.Time { return now },
		Logger:    testLogger{},
	}
	for name, deps := range map[string]Dependencies{
		"lifecycle": {Clock: valid.Clock, Logger: valid.Logger},
		"clock":     {Lifecycle: valid.Lifecycle, Logger: valid.Logger},
		"logger":    {Lifecycle: valid.Lifecycle, Clock: valid.Clock},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newServer(deps); err == nil {
				t.Fatal("newServer() succeeded with a missing dependency")
			}
		})
	}
	if _, err := newServer(valid); err != nil {
		t.Fatalf("newServer(valid) error = %v", err)
	}
}

func TestHandlersUseInjectedLifecycleService(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	fake := &fakeLifecycle{
		identities: []lifecycle.Identity{{
			ID: "fake-identity", Name: "fake-identity", Provider: "fake-provider", Environment: "test",
			Owner: "Test Team", Workload: "Test workload", Criticality: "low", State: lifecycle.StateActive,
			RenewalHealth: lifecycle.RenewalHealthy, ExpiresAt: now.Add(90 * 24 * time.Hour),
		}},
		events: map[string][]lifecycle.Event{},
	}
	handler, err := NewServer(Dependencies{Lifecycle: fake, Clock: func() time.Time { return now }, Logger: testLogger{}})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/identities/fake-identity/rotate", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if fake.rotatedID != "fake-identity" {
		t.Fatalf("Rotate() received %q, want fake-identity", fake.rotatedID)
	}
}

func TestDashboardRendersProductAndInteractionSurface(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	for _, expected := range []string{
		"Govern what",
		"must change.",
		"Say it in Latin",
		"moo-TAHN-dye",
		"hx-post=\"/identities/payments-api/rotate\"",
		"x-data=\"{ filter: '', status: 'all', navOpen: false }\"",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("dashboard does not contain %q", expected)
		}
	}
}

func TestDashboardSummarySeparatesExpiringAndOverdue(t *testing.T) {
	server := testServer(t)
	view := server.dashboardView()
	if view.Total != 4 || view.Healthy != 1 || view.Expiring != 2 || view.Attention != 2 {
		t.Fatalf("summary = (total=%d healthy=%d expiring=%d attention=%d), want (4, 1, 2, 2)", view.Total, view.Healthy, view.Expiring, view.Attention)
	}
}

func TestRotateRefreshesIdentityAndEvents(t *testing.T) {
	handler := testHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/identities/payments-api/rotate", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), "Due in 90 days") {
		t.Fatalf("rotated identity list does not show the new 90-day expiry")
	}

	eventsRequest := httptest.NewRequest(http.MethodGet, "/identities/payments-api/events", nil)
	eventsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(eventsRecorder, eventsRequest)
	if eventsRecorder.Code != http.StatusOK {
		t.Fatalf("events status = %d, want %d", eventsRecorder.Code, http.StatusOK)
	}
	for _, expected := range []string{"rotation.completed", "New credential verified", "success"} {
		if !strings.Contains(eventsRecorder.Body.String(), expected) {
			t.Errorf("events response does not contain %q", expected)
		}
	}
}

func TestAPIAndHealthEndpoints(t *testing.T) {
	handler := testHandler(t)

	apiRecorder := httptest.NewRecorder()
	handler.ServeHTTP(apiRecorder, httptest.NewRequest(http.MethodGet, "/api/identities", nil))
	if apiRecorder.Code != http.StatusOK {
		t.Fatalf("API status = %d, want %d", apiRecorder.Code, http.StatusOK)
	}
	var identities []map[string]any
	if err := json.Unmarshal(apiRecorder.Body.Bytes(), &identities); err != nil {
		t.Fatalf("decode API response: %v", err)
	}
	if len(identities) != 4 {
		t.Fatalf("API returned %d identities, want 4", len(identities))
	}

	for _, path := range []string{"/livez", "/readyz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != "ok\n" {
			t.Errorf("%s response = (%d, %q), want (200, %q)", path, recorder.Code, recorder.Body.String(), "ok\n")
		}
	}
}

func TestMissingIdentity(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/identities/missing/events", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
