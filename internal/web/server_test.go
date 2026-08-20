package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/pkg/protocol"
)

func testNow() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

// testStore wires the real control-plane store to the simulated Azure adapter,
// exercising the same provider boundary main() uses.
func testStore(t *testing.T) *lifecycle.Store {
	t.Helper()
	store, err := lifecycle.NewStore(context.Background(), testNow(), provider.NewSimulator("tenant-1", testNow()))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store
}

func testServer(t *testing.T) *Server {
	t.Helper()
	server, err := newServer(Dependencies{
		Lifecycle:     testStore(t),
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
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

type testConfiguration struct{}

func (testConfiguration) Configuration() protocol.Configuration {
	return protocol.Configuration{
		Service: "mutandae-control-plane", ProtocolVersion: protocol.Version,
		MediaType: protocol.MediaType, Environment: "preview",
		Provider: "azure-entra (simulated)", Persistence: "in-memory",
		ReadOnly: true, Features: []string{"Synthetic data only"}, UpdatedAt: testNow(),
	}
}

func TestNewServerRequiresDependencies(t *testing.T) {
	valid := Dependencies{
		Lifecycle:     testStore(t),
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	}
	for name, deps := range map[string]Dependencies{
		"lifecycle":     {Configuration: valid.Configuration, Clock: valid.Clock, Logger: valid.Logger},
		"configuration": {Lifecycle: valid.Lifecycle, Clock: valid.Clock, Logger: valid.Logger},
		"clock":         {Lifecycle: valid.Lifecycle, Configuration: valid.Configuration, Logger: valid.Logger},
		"logger":        {Lifecycle: valid.Lifecycle, Configuration: valid.Configuration, Clock: valid.Clock},
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
	fake := &fakeLifecycle{
		identities: []protocol.MachineIdentity{{
			ID: "fake-identity", Name: "fake-identity", Environment: "test",
			Provider:  protocol.ProviderBinding{Provider: "azure-entra", ProviderID: "obj-1", TenantID: "t1"},
			Ownership: protocol.Ownership{Team: "Test Team", Service: "Test workload", Purpose: "test", Criticality: "low"},
			Policy:    protocol.LifecyclePolicy{RenewalPeriod: "P90D"},
			State:     protocol.StateActive, Health: protocol.HealthHealthy,
			ExpiresAt: testNow().Add(90 * 24 * time.Hour),
		}},
		events: map[string][]protocol.LifecycleEvent{},
	}
	handler, err := NewServer(Dependencies{Lifecycle: fake, Configuration: testConfiguration{}, Clock: func() time.Time { return testNow() }, Logger: testLogger{}})
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

func TestConfigurationPageAndProtocolEndpointAreSafe(t *testing.T) {
	handler := testHandler(t)
	for _, path := range []string{"/configuration", "/api/v1/configuration"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, recorder.Code)
		}
		body := recorder.Body.String()
		if strings.Contains(body, "redis://") || strings.Contains(body, "REDIS_URL") || strings.Contains(body, "tenant-1") || strings.Contains(body, "client_secret") {
			t.Fatalf("%s exposed forbidden runtime data: %s", path, body)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/configuration", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /configuration status = %d, want 405", recorder.Code)
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
		"moo-TAHN-dye",
		"Azure / Entra ID",
		"Azure simulator",
		"hx-post=\"/identities/payments-api/rotate\"",
		"hx-post=\"/identities/payments-api/retire\"",
		"x-data=\"{ filter: '', status: 'all', navOpen: false }\"",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("dashboard does not contain %q", expected)
		}
	}
}

func TestDashboardSummarySeparatesExpiringAndOverdue(t *testing.T) {
	view := testServer(t).dashboardView()
	if view.Total != 4 || view.Healthy != 1 || view.Expiring != 2 || view.Attention != 2 {
		t.Fatalf("summary = (total=%d healthy=%d expiring=%d attention=%d), want (4, 1, 2, 2)", view.Total, view.Healthy, view.Expiring, view.Attention)
	}
	if view.Provider != "azure-entra" || view.TenantID != "tenant-1" {
		t.Fatalf("provider/tenant = (%q, %q), want (azure-entra, tenant-1)", view.Provider, view.TenantID)
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

func TestRetireMovesIdentityOutOfGovernance(t *testing.T) {
	handler := testHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/identities/payments-api/retire", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), "Retired") {
		t.Fatalf("retired list does not reflect the retired badge")
	}
}

func TestProtocolAPI(t *testing.T) {
	handler := testHandler(t)

	// Discovery index.
	root := requestJSON(t, handler, http.MethodGet, "/api/v1/")
	if root["api_version"] != protocol.Version {
		t.Fatalf("discovery api_version = %v, want %s", root["api_version"], protocol.Version)
	}
	resources, ok := root["resources"].([]any)
	if !ok || len(resources) == 0 {
		t.Fatalf("discovery resources missing: %v", root["resources"])
	}

	// List returns a conformant protocol inventory.
	list := requestJSON(t, handler, http.MethodGet, "/api/v1/identities")
	var listResp protocol.ListResponse
	raw, _ := json.Marshal(list)
	if err := json.Unmarshal(raw, &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listResp.APIVersion != protocol.Version || listResp.Total != 4 {
		t.Fatalf("list = (version=%q total=%d), want (v1, 4)", listResp.APIVersion, listResp.Total)
	}
	for i := range listResp.Identities {
		if err := protocol.ValidateIdentity(&listResp.Identities[i]); err != nil {
			t.Errorf("identity %q not conformant over the wire: %v", listResp.Identities[i].ID, err)
		}
	}

	// Inspect a single identity.
	inspect := requestJSON(t, handler, http.MethodGet, "/api/v1/identities/payments-api")
	if inspect["identity"].(map[string]any)["id"] != "payments-api" {
		t.Fatalf("inspect identity id not found: %v", inspect)
	}

	// Rotate via the protocol API returns correlation + evidence.
	rotate := requestJSON(t, handler, http.MethodPost, "/api/v1/identities/payments-api/rotations")
	var rotResp protocol.RotateResponse
	rb, _ := json.Marshal(rotate)
	if err := json.Unmarshal(rb, &rotResp); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	if rotResp.Rotation.Status != protocol.RotationSucceeded || rotResp.Identity.Credential.KeyID == "" {
		t.Fatalf("rotate = %+v, want succeeded with credential evidence", rotResp)
	}

	// Missing identity yields a conformant failure envelope.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/identities/nope", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", recorder.Code)
	}
	var missing map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &missing); err != nil {
		t.Fatalf("decode missing envelope: %v", err)
	}
	if missing["error"].(map[string]any)["code"] != string(protocol.ErrCodeNotFound) {
		t.Fatalf("missing error envelope = %v", missing["error"])
	}
}

func TestProtocolContentType(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/identities", nil))
	if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, protocol.MediaType) {
		t.Fatalf("Content-Type = %q, want protocol media type", got)
	}
}

func TestHealthEndpoints(t *testing.T) {
	handler := testHandler(t)
	for _, path := range []string{"/livez", "/readyz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Body.String() != "ok\n" {
			t.Errorf("%s response = (%d, %q), want (200, %q)", path, recorder.Code, recorder.Body.String(), "ok\n")
		}
	}
}

func TestMissingIdentity(t *testing.T) {
	handler := testHandler(t)
	for _, path := range []string{"/identities/missing/events", "/api/v1/identities/missing"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}
}

func requestJSON(t *testing.T, handler http.Handler, method, path string) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	if recorder.Code < 200 || recorder.Code >= 300 {
		t.Fatalf("%s %s status = %d, want 2xx: %s", method, path, recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	return payload
}

// fakeLifecycle is a consumer-side fake used to prove handlers depend on the
// small boundary rather than the concrete store.
type fakeLifecycle struct {
	identities []protocol.MachineIdentity
	events     map[string][]protocol.LifecycleEvent
	rotatedID  string
}

func (f *fakeLifecycle) List() []protocol.MachineIdentity {
	return append([]protocol.MachineIdentity(nil), f.identities...)
}

func (f *fakeLifecycle) Get(id string) (protocol.MachineIdentity, bool) {
	for _, identity := range f.identities {
		if identity.ID == id {
			return identity, true
		}
	}
	return protocol.MachineIdentity{}, false
}

func (f *fakeLifecycle) Events(id string) ([]protocol.LifecycleEvent, bool) {
	events, ok := f.events[id]
	return append([]protocol.LifecycleEvent(nil), events...), ok
}

func (f *fakeLifecycle) Runs(id string) ([]protocol.RotationRun, bool) { return nil, false }

func (f *fakeLifecycle) Register(_ context.Context, req protocol.RegisterRequest, now time.Time) (protocol.RegisterResponse, error) {
	return protocol.RegisterResponse{APIVersion: protocol.Version}, nil
}

func (f *fakeLifecycle) Rotate(_ context.Context, req protocol.RotateRequest, now time.Time) (protocol.RotateResponse, error) {
	f.rotatedID = req.ID
	identity, ok := f.Get(req.ID)
	if !ok {
		return protocol.RotateResponse{}, lifecycle.ErrNotFound
	}
	identity.LastRotatedAt = now
	return protocol.RotateResponse{APIVersion: protocol.Version, Identity: identity, Rotation: protocol.RotationRun{ID: "run-x", Status: protocol.RotationSucceeded}}, nil
}

func (f *fakeLifecycle) Retire(_ context.Context, req protocol.RetireRequest, now time.Time) (protocol.RetireResponse, error) {
	identity, ok := f.Get(req.ID)
	if !ok {
		return protocol.RetireResponse{}, lifecycle.ErrNotFound
	}
	identity.State = protocol.StateRetired
	return protocol.RetireResponse{APIVersion: protocol.Version, Identity: identity}, nil
}
