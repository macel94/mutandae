package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mutandae/mutandae/internal/buildinfo"
	"github.com/mutandae/mutandae/internal/config"
	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/pkg/protocol"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// LifecycleService is the web layer's small consumer-defined boundary, mirroring
// the control-plane operations. The production implementation is lifecycle.Store;
// tests and future adapters can substitute a fake without changing handlers.
// Everything exchanged across the boundary is a μTandae Protocol type, so both
// the server-rendered frontend and the JSON protocol API speak the same contract.
type LifecycleService interface {
	List() []protocol.MachineIdentity
	Get(id string) (protocol.MachineIdentity, bool)
	Events(id string) ([]protocol.LifecycleEvent, bool)
	Runs(id string) ([]protocol.RotationRun, bool)
	Register(ctx context.Context, req protocol.RegisterRequest, now time.Time) (protocol.RegisterResponse, error)
	Rotate(ctx context.Context, req protocol.RotateRequest, now time.Time) (protocol.RotateResponse, error)
	Retire(ctx context.Context, req protocol.RetireRequest, now time.Time) (protocol.RetireResponse, error)
	Provision(ctx context.Context, req protocol.ProvisionRequest, now time.Time) (protocol.ProvisionResponse, error)
	Use(ctx context.Context, req protocol.UseRequest, now time.Time) (protocol.UseResponse, error)
}

// ConfigurationService supplies only the safe, read-only runtime view.
type ConfigurationService interface {
	Configuration() protocol.Configuration
}

// Clock makes time-dependent rendering and mutations deterministic in tests.
type Clock func() time.Time

// Logger is intentionally smaller than a concrete logging implementation.
type Logger interface {
	Printf(format string, args ...any)
}

type Dependencies struct {
	Lifecycle     LifecycleService
	Configuration ConfigurationService
	Integration   lifecycle.IntegrationService
	Clock         Clock
	Logger        Logger
	RateLimit     RateLimitConfig
	// DemoLimit caps the concurrently active demo identities per provider;
	// zero falls back to 40.
	DemoLimit int
}

type Server struct {
	lifecycle     LifecycleService
	templates     *template.Template
	static        fs.FS
	now           Clock
	logger        Logger
	configuration ConfigurationService
	integration   lifecycle.IntegrationService
	build         buildView
	readLimiter   *rateLimiter
	writeLimiter  *rateLimiter
	createLimiter *rateLimiter
	rateLimit     RateLimitConfig
	demoLimit     int
}

var _ LifecycleService = (*lifecycle.Store)(nil)

func NewServer(deps Dependencies) (http.Handler, error) {
	server, err := newServer(deps)
	if err != nil {
		return nil, err
	}
	return server.routes(), nil
}

func newServer(deps Dependencies) (*Server, error) {
	if deps.Lifecycle == nil {
		return nil, errors.New("lifecycle service is required")
	}
	if deps.Configuration == nil {
		return nil, errors.New("configuration service is required")
	}
	if deps.Clock == nil {
		return nil, errors.New("clock is required")
	}
	if deps.Logger == nil {
		return nil, errors.New("logger is required")
	}

	templates, err := template.New("mutandae").Funcs(template.FuncMap{
		"formatDate": func(value time.Time) string { return value.Format("Jan 02, 2006") },
		"formatTime": func(value time.Time) string { return value.Format("Jan 02, 2006 · 15:04 MST") },
		"eventClass": func(outcome protocol.Outcome) string {
			switch outcome {
			case protocol.OutcomeSuccess:
				return "event-success"
			case protocol.OutcomeAttention, protocol.OutcomeFailure:
				return "event-attention"
			default:
				return "event-progress"
			}
		},
		"shortVersion": func(version string) string {
			if len(version) <= 12 {
				return version
			}
			return version[:8] + "…"
		},
		"newIdentity": func(providers []providerSummary, target string) map[string]any {
			return map[string]any{"Providers": providers, "Target": target}
		},
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	cfg := deps.RateLimit.defaults()
	demoLimit := deps.DemoLimit
	if demoLimit <= 0 {
		demoLimit = 40
	}
	return &Server{
		lifecycle:     deps.Lifecycle,
		configuration: deps.Configuration,
		integration:   deps.Integration,
		build:         toBuildView(),
		templates:     templates,
		static:        static,
		now:           deps.Clock,
		logger:        deps.Logger,
		rateLimit:     cfg,
		demoLimit:     demoLimit,
	}, nil
}

func (s *Server) routes() http.Handler {
	if s.readLimiter == nil {
		cfg := s.rateLimit.defaults()
		s.readLimiter = newRateLimiter(cfg.ReadRate, cfg.ReadBurst, 10000, s.now)
		s.writeLimiter = newRateLimiter(cfg.WriteRate, cfg.WriteBurst, 10000, s.now)
		s.createLimiter = newRateLimiter(cfg.CreateRate, cfg.CreateBurst, 10000, s.now)
	}
	mux := http.NewServeMux()
	// Server-rendered frontend (HTMX + CSP-safe vanilla JS in /static/app.js).
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /configuration", s.configurationPage)
	mux.HandleFunc("GET /api/v1/integration/requirements", s.apiIntegrationRequirements)
	mux.HandleFunc("POST /api/v1/integration/connect", s.apiIntegrationConnect)
	mux.HandleFunc("GET /api/v1/integration/session", s.apiIntegrationSession)
	mux.HandleFunc("POST /api/v1/integration/disconnect", s.apiIntegrationDisconnect)
	mux.HandleFunc("GET /api/v1/integration/applications", s.apiIntegrationApplications)
	mux.HandleFunc("POST /api/v1/integration/applications", s.apiIntegrationCreateApplication)
	mux.HandleFunc("POST /api/v1/integration/secrets", s.apiIntegrationCreateSecret)
	mux.HandleFunc("POST /api/v1/integration/secrets/read", s.apiIntegrationReadSecret)
	mux.HandleFunc("POST /api/v1/integration/secrets/invalidate", s.apiIntegrationInvalidateSecret)
	mux.HandleFunc("GET /partials/identities", s.identityList)
	mux.HandleFunc("GET /identities/{id}/events", s.identityEvents)
	mux.HandleFunc("POST /identities/{id}/rotate", s.rotate)
	mux.HandleFunc("POST /identities/{id}/retire", s.retire)
	mux.HandleFunc("POST /identities/{id}/use", s.use)
	mux.HandleFunc("POST /identities/provision", s.provision)
	// Protocol JSON API (versioned).
	mux.HandleFunc("GET /api/v1/", s.apiRoot)
	mux.HandleFunc("GET /api/v1/configuration", s.apiConfiguration)
	mux.HandleFunc("GET /api/v1/identities", s.apiList)
	mux.HandleFunc("POST /api/v1/identities", s.apiRegister)
	mux.HandleFunc("GET /api/v1/identities/{id}", s.apiInspect)
	mux.HandleFunc("POST /api/v1/identities/{id}/rotations", s.apiRotate)
	mux.HandleFunc("POST /api/v1/identities/{id}/retire", s.apiRetire)
	mux.HandleFunc("POST /api/v1/identities/{id}/use", s.apiUse)
	mux.HandleFunc("POST /api/v1/demo/identities", s.apiProvision)
	// Health probes.
	mux.HandleFunc("GET /livez", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	// Favicon: browsers request /favicon.ico even without an HTML link.
	mux.HandleFunc("GET /favicon.ico", s.faviconICO)
	mux.HandleFunc("GET /favicon.svg", s.faviconSVG)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.static))))
	return securityHeaders(throttle(s.readLimiter, s.writeLimiter, s.createLimiter, mux))
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index", s.dashboardView())
}

func (s *Server) configurationPage(w http.ResponseWriter, r *http.Request) {
	view := configurationPageView{Configuration: s.configuration.Configuration(), Build: s.build}
	view.Provision = s.provisionableProviders()
	if s.integration != nil {
		view.IntegrationEnabled = true
		view.Requirements = s.integration.Requirements()
	}
	ensureCSRFCookie(w, r)
	s.render(w, "configuration", view)
}

func (s *Server) identityList(w http.ResponseWriter, r *http.Request) {
	s.render(w, "identity-list", s.dashboardView())
}

func (s *Server) identityEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	identity, ok := s.lifecycle.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	events, _ := s.lifecycle.Events(id)
	s.render(w, "events", eventsView{
		Identity: toIdentityView(identity, s.now()),
		Events:   events,
	})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	req := protocol.RotateRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
		Reason:      "operator initiated from dashboard",
	}
	_, err := s.lifecycle.Rotate(r.Context(), req, s.now())
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	s.identityList(w, r)
}

func (s *Server) retire(w http.ResponseWriter, r *http.Request) {
	req := protocol.RetireRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
		Reason:      "operator initiated from dashboard",
		Confirm:     true,
	}
	_, err := s.lifecycle.Retire(r.Context(), req, s.now())
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	s.identityList(w, r)
}

// provision creates a new zero-permission identity in a real tenant from the
// dashboard or configuration page, applying the per-provider quota and
// returning a fragment that discloses the one-time secret exactly once, reports
// the vault delivery, and refreshes the inventory out-of-band. The provider is
// accepted as a form field (new-identity dropdown) or query parameter.
func (s *Server) provision(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PostFormValue("provider"))
	if provider == "" {
		provider = strings.TrimSpace(r.URL.Query().Get("provider"))
	}
	if provider == "" {
		s.writeError(w, errors.New("provider is required"), http.StatusBadRequest)
		return
	}
	resp, err := s.provisionIdentity(r, provider, r.PostFormValue("purpose"))
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	// The dashboard posts into a dedicated slot; answer with the compact result
	// fragment plus an out-of-band inventory refresh. The configuration page
	// keeps receiving the full provision template.
	if r.Header.Get("HX-Target") == "provision-slot" {
		s.render(w, "provision-result", provisionResultView{
			Identity:  toIdentityView(resp.Identity, s.now()),
			KeyID:     resp.KeyID,
			Secret:    resp.OneTimeSecret,
			Vault:     resp.Vault,
			VaultName: vaultReferenceName(resp.Vault, resp.Identity.Provider.Provider),
			Dashboard: s.dashboardView(),
		})
		return
	}
	s.render(w, "provision", provisionView{
		Identity:     toIdentityView(resp.Identity, s.now()),
		KeyID:        resp.KeyID,
		Secret:       resp.OneTimeSecret,
		Vault:        resp.Vault,
		VaultName:    vaultReferenceName(resp.Vault, resp.Identity.Provider.Provider),
		Instructions: resp.Instructions,
		Dashboard:    s.dashboardView(),
	})
}

// use retrieves the current credential of one identity from its selected
// provider-native vault, auditing the retrieval, and renders the result into
// the activity panel.
func (s *Server) use(w http.ResponseWriter, r *http.Request) {
	resp, err := s.lifecycle.Use(r.Context(), protocol.UseRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
	}, s.now())
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	s.render(w, "use-result", useResultView{
		Identity:  toIdentityView(resp.Identity, s.now()),
		KeyID:     resp.KeyID,
		Secret:    resp.Secret,
		Vault:     resp.Vault,
		VaultName: vaultReferenceName(resp.Vault, resp.Identity.Provider.Provider),
	})
}

// --- Protocol JSON API ---

func (s *Server) apiRoot(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, protocol.DiscoveryIndex{
		APIVersion: protocol.Version,
		Service:    "mutandae-control-plane",
		MediaType:  protocol.MediaType,
		Resources: []protocol.DiscoveryResource{
			{Rel: "configuration", Method: http.MethodGet, HREF: "/api/v1/configuration", Envelope: "configuration"},
			{Rel: "integration-requirements", Method: http.MethodGet, HREF: "/api/v1/integration/requirements", Envelope: "requirements"},
			{Rel: "integration-connect", Method: http.MethodPost, HREF: "/api/v1/integration/connect", Envelope: "integration"},
			{Rel: "integration-session", Method: http.MethodGet, HREF: "/api/v1/integration/session", Envelope: "integration"},
			{Rel: "applications", Method: http.MethodGet, HREF: "/api/v1/integration/applications", Envelope: "applications"},
			{Rel: "application-create", Method: http.MethodPost, HREF: "/api/v1/integration/applications", Envelope: "application"},
			{Rel: "secret-create", Method: http.MethodPost, HREF: "/api/v1/integration/secrets", Envelope: "secret"},
			{Rel: "secret-read", Method: http.MethodPost, HREF: "/api/v1/integration/secrets/read", Envelope: "secret"},
			{Rel: "secret-invalidate", Method: http.MethodPost, HREF: "/api/v1/integration/secrets/invalidate", Envelope: "secret"},
			{Rel: "identities", Method: http.MethodGet, HREF: "/api/v1/identities", Envelope: "list"},
			{Rel: "identity", Method: http.MethodGet, HREF: "/api/v1/identities/{id}", Envelope: "inspect"},
			{Rel: "register", Method: http.MethodPost, HREF: "/api/v1/identities", Envelope: "register"},
			{Rel: "rotate", Method: http.MethodPost, HREF: "/api/v1/identities/{id}/rotations", Envelope: "rotate"},
			{Rel: "retire", Method: http.MethodPost, HREF: "/api/v1/identities/{id}/retire", Envelope: "retire"},
		},
	})
}

func (s *Server) apiConfiguration(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, protocol.ConfigurationResponse{
		APIVersion:    protocol.Version,
		Configuration: s.configuration.Configuration(),
	})
}

func (s *Server) apiIntegrationRequirements(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, protocol.AzureIntegrationRequirementsResponse{APIVersion: protocol.Version, Requirements: s.integration.Requirements()})
}

func (s *Server) apiIntegrationConnect(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	if !requestIsSecure(r) && r.RemoteAddr != "" && !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") && !strings.HasPrefix(r.RemoteAddr, "[::1]:") {
		s.writeIntegrationFailure(w, http.StatusUpgradeRequired, "real-tenant credentials require HTTPS")
		return
	}
	var req protocol.AzureIntegrationRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeIntegrationFailure(w, http.StatusBadRequest, "invalid integration request")
		return
	}
	csrf := csrfCookie(r)
	session, sessionCSRF, err := s.integration.Connect(r.Context(), req, csrf, integrationRateKey(r), s.now())
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	setCookie(w, r, integrationSessionCookie, session.ID, true)
	setCookie(w, r, csrfCookieName, sessionCSRF, false)
	s.writeJSON(w, http.StatusOK, protocol.AzureIntegrationResponse{APIVersion: protocol.Version, Session: session, CSRFToken: sessionCSRF})
}

func (s *Server) apiIntegrationSession(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	sessionID, ok := requestCookie(r, integrationSessionCookie)
	if !ok {
		s.writeIntegrationFailure(w, http.StatusUnauthorized, lifecycle.ErrIntegrationSessionNotFound.Error())
		return
	}
	session, err := s.integration.SessionView(sessionID, csrfCookie(r), s.now())
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, protocol.AzureIntegrationResponse{APIVersion: protocol.Version, Session: session})
}

func (s *Server) apiIntegrationDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	if sessionID, ok := requestCookie(r, integrationSessionCookie); ok {
		s.integration.Disconnect(sessionID)
	}
	clearCookie(w, r, integrationSessionCookie, true)
	s.writeJSON(w, http.StatusOK, map[string]any{"api_version": protocol.Version, "disconnected": true})
}

func integrationRateKey(r *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}

func (s *Server) integrationSession(r *http.Request) (string, string, error) {
	sessionID, ok := requestCookie(r, integrationSessionCookie)
	if !ok {
		return "", "", lifecycle.ErrIntegrationSessionNotFound
	}
	csrf := csrfCookie(r)
	if err := validateCSRF(r, false); err != nil {
		return "", "", err
	}
	return sessionID, csrf, nil
}

func (s *Server) apiIntegrationApplications(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	sessionID, csrf, err := s.integrationSession(r)
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	applications, receipt, err := s.integration.ListApplications(r.Context(), sessionID, csrf, s.now())
	status := http.StatusOK
	if err != nil {
		status = integrationStatus(err)
	}
	s.writeJSON(w, status, protocol.AzureApplicationsResponse{APIVersion: protocol.Version, Applications: applications, Receipt: receipt, Error: integrationError(err)})
}

func (s *Server) apiIntegrationCreateApplication(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	sessionID, csrf, err := s.integrationSession(r)
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	var req protocol.AzureApplicationCreateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeIntegrationFailure(w, http.StatusBadRequest, "invalid application request")
		return
	}
	application, receipt, err := s.integration.CreateApplication(r.Context(), sessionID, csrf, req, s.now())
	status := http.StatusCreated
	if err != nil {
		status = integrationStatus(err)
	}
	s.writeJSON(w, status, protocol.AzureApplicationResponse{APIVersion: protocol.Version, Application: application, Receipt: &receipt, Error: integrationError(err)})
}

func (s *Server) apiIntegrationCreateSecret(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	sessionID, csrf, err := s.integrationSession(r)
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	var req protocol.AzureSecretCreateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeIntegrationFailure(w, http.StatusBadRequest, "invalid secret request")
		return
	}
	secret, receipt, err := s.integration.CreateSecret(r.Context(), sessionID, csrf, req, s.now())
	status := http.StatusCreated
	if err != nil {
		status = integrationStatus(err)
	}
	s.writeJSON(w, status, protocol.AzureSecretResponse{APIVersion: protocol.Version, Secret: secret, Receipt: receipt, Error: integrationError(err)})
}

func (s *Server) apiIntegrationReadSecret(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	sessionID, csrf, err := s.integrationSession(r)
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	var req protocol.AzureSecretReadRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeIntegrationFailure(w, http.StatusBadRequest, "invalid secret read request")
		return
	}
	secret, receipt, err := s.integration.ReadSecret(r.Context(), sessionID, csrf, req, s.now())
	status := http.StatusOK
	if err != nil {
		status = integrationStatus(err)
	}
	s.writeJSON(w, status, protocol.AzureSecretReadResponse{APIVersion: protocol.Version, Secret: secret, Receipt: receipt, Error: integrationError(err)})
}

func (s *Server) apiIntegrationInvalidateSecret(w http.ResponseWriter, r *http.Request) {
	if s.integration == nil {
		s.writeIntegrationFailure(w, http.StatusNotImplemented, "interactive Azure integration is not enabled")
		return
	}
	if err := validateCSRF(r, true); err != nil {
		s.writeIntegrationFailure(w, http.StatusForbidden, err.Error())
		return
	}
	sessionID, csrf, err := s.integrationSession(r)
	if err != nil {
		s.writeIntegrationFailure(w, integrationStatus(err), err.Error())
		return
	}
	var req protocol.AzureSecretInvalidateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		s.writeIntegrationFailure(w, http.StatusBadRequest, "invalid secret invalidation request")
		return
	}
	credential, receipt, err := s.integration.InvalidateSecret(r.Context(), sessionID, csrf, req, s.now())
	status := http.StatusOK
	if err != nil {
		status = integrationStatus(err)
	}
	s.writeJSON(w, status, protocol.AzureSecretInvalidateResponse{APIVersion: protocol.Version, Credential: credential, Receipt: receipt, Error: integrationError(err)})
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request) {
	identities := s.lifecycle.List()
	s.writeJSON(w, http.StatusOK, protocol.ListResponse{
		APIVersion: protocol.Version,
		Total:      len(identities),
		Identities: identities,
	})
}

func (s *Server) apiInspect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	identity, ok := s.lifecycle.Get(id)
	if !ok {
		s.writeJSON(w, http.StatusNotFound, protocol.Failure(protocol.NewError(protocol.ErrCodeNotFound, "identity not found")))
		return
	}
	s.writeJSON(w, http.StatusOK, protocol.InspectResponse{APIVersion: protocol.Version, Identity: identity})
}

func (s *Server) apiRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, protocol.Failure(protocol.NewError(protocol.ErrCodeInvalidRequest, "invalid request body")))
		return
	}
	resp, err := s.lifecycle.Register(r.Context(), req, s.now())
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, protocol.Failure(lifecycle.NewError(err)))
		return
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) apiProvision(w http.ResponseWriter, r *http.Request) {
	var req protocol.ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, protocol.Failure(protocol.NewError(protocol.ErrCodeInvalidRequest, "invalid request body")))
		return
	}
	resp, err := s.provisionIdentity(r, req.Provider, req.Purpose)
	if err != nil {
		s.writeJSON(w, http.StatusConflict, protocol.Failure(lifecycle.NewError(err)))
		return
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) apiUse(w http.ResponseWriter, r *http.Request) {
	var req protocol.UseRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeJSON(w, http.StatusBadRequest, protocol.Failure(protocol.NewError(protocol.ErrCodeInvalidRequest, "invalid request body")))
			return
		}
	}
	req.ID = r.PathValue("id")
	req.RequestedBy = operatorOrDefault(r)
	resp, err := s.lifecycle.Use(r.Context(), req, s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, lifecycle.ErrNotFound) {
			status = http.StatusNotFound
		}
		s.writeJSON(w, status, protocol.Failure(lifecycle.NewError(err)))
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// provisionIdentity applies the per-provider demo quota (auto-reclaiming the
// oldest idle demo identity when at capacity) and delegates to the control
// plane's Provision, which never persists the one-time secret. The hint is
// sanitized by the provider (buildDemoName) and defaults to empty.
func (s *Server) provisionIdentity(r *http.Request, provider, hint string) (protocol.ProvisionResponse, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return protocol.ProvisionResponse{}, errors.New("provider is required")
	}
	s.reclaimDemo(r.Context(), provider)
	req := protocol.ProvisionRequest{
		Provider:    provider,
		Purpose:     strings.TrimSpace(hint),
		RequestedBy: operatorOrDefault(r),
		OwnerIP:     clientIP(r),
	}
	resp, err := s.lifecycle.Provision(r.Context(), req, s.now())
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	return resp, nil
}

// maxActiveDemo per provider keeps a public demo from growing a tenant without
// bound while the least-privilege server credentials stay the real safety
// boundary.
func (s *Server) reclaimDemo(ctx context.Context, provider string) {
	limit := s.demoLimit
	if limit <= 0 {
		limit = 40
	}
	for {
		demo := s.activeDemo(provider)
		if len(demo) < limit {
			return
		}
		oldest := demo[0]
		for _, candidate := range demo[1:] {
			if candidate.CreatedAt.Before(oldest.CreatedAt) {
				oldest = candidate
			}
		}
		_, err := s.lifecycle.Retire(ctx, protocol.RetireRequest{
			ID:          oldest.ID,
			Confirm:     true,
			RequestedBy: "demo-reclaim",
			Reason:      "demo quota reached — oldest demo identity reclaimed",
		}, s.now())
		if err != nil {
			return
		}
	}
}

func (s *Server) activeDemo(provider string) []protocol.MachineIdentity {
	var demo []protocol.MachineIdentity
	for _, identity := range s.lifecycle.List() {
		if identity.Provider.Provider == provider && identity.State == protocol.StateActive && strings.HasPrefix(identity.Name, demoPrefixWeb) {
			demo = append(demo, identity)
		}
	}
	return demo
}

func (s *Server) apiRotate(w http.ResponseWriter, r *http.Request) {
	req := protocol.RotateRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
		Reason:      "protocol api",
	}
	resp, err := s.lifecycle.Rotate(r.Context(), req, s.now())
	if err != nil {
		s.writeJSON(w, http.StatusConflict, protocol.Failure(lifecycle.NewError(err)))
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) apiRetire(w http.ResponseWriter, r *http.Request) {
	var body protocol.RetireRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.writeJSON(w, http.StatusBadRequest, protocol.Failure(protocol.NewError(protocol.ErrCodeInvalidRequest, "invalid request body")))
			return
		}
	}
	body.ID = r.PathValue("id")
	body.RequestedBy = operatorOrDefault(r)
	resp, err := s.lifecycle.Retire(r.Context(), body, s.now())
	if err != nil {
		s.writeJSON(w, http.StatusConflict, protocol.Failure(lifecycle.NewError(err)))
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Printf("encode protocol payload: %v", err)
	}
}

const (
	csrfCookieName           = "mutandae_csrf"
	integrationSessionCookie = "mutandae_integration"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if value := csrfCookie(r); value != "" {
		return value
	}
	value := randomToken()
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: value, Path: "/", HttpOnly: false, Secure: requestIsSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	return value
}

func csrfCookie(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func validateCSRF(r *http.Request, requireHeader bool) error {
	cookie := csrfCookie(r)
	if cookie == "" {
		return lifecycle.ErrIntegrationCSRF
	}
	if requireHeader && !secureStringEqual(cookie, r.Header.Get("X-Mutandae-CSRF")) {
		return lifecycle.ErrIntegrationCSRF
	}
	return nil
}

func secureStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}

func randomToken() string {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().String()))
	}
	return hex.EncodeToString(raw[:])
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: httpOnly, Secure: requestIsSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: 1800})
}

func clearCookie(w http.ResponseWriter, r *http.Request, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: httpOnly, Secure: requestIsSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

func requestCookie(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func integrationStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case errors.Is(err, lifecycle.ErrIntegrationSessionNotFound):
		return http.StatusUnauthorized
	case errors.Is(err, lifecycle.ErrIntegrationCSRF):
		return http.StatusForbidden
	case errors.Is(err, lifecycle.ErrIntegrationRateLimited):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func integrationError(err error) *protocol.Error {
	if err == nil {
		return nil
	}
	return ptr(protocol.NewError(protocol.ErrCodeProviderFailure, err.Error()))
}

func (s *Server) writeIntegrationFailure(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, protocol.Failure(protocol.NewError(protocol.ErrCodeInvalidRequest, message)))
}

func ptr[T any](value T) *T { return &value }

// writeError writes a browser-readable error for the HTML actions, mapping
// lifecycle errors onto appropriate HTTP status codes.
func (s *Server) writeError(w http.ResponseWriter, err error, defaultStatus int) {
	status := defaultStatus
	if errors.Is(err, lifecycle.ErrNotFound) {
		status = http.StatusNotFound
	}
	http.Error(w, err.Error(), status)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// faviconICO serves the μTandae mark as a multi-size ICO fallback.
func (s *Server) faviconICO(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	http.ServeFileFS(w, r, s.static, "favicon.ico")
}

// faviconSVG serves the μTandae mark as a scalable SVG icon.
func (s *Server) faviconSVG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	http.ServeFileFS(w, r, s.static, "favicon.svg")
}

func operatorOrDefault(r *http.Request) string {
	if operator := r.Header.Get("X-Mutandae-Operator"); operator != "" {
		return operator
	}
	return "demo-operator"
}

func (s *Server) dashboardView() dashboardView {
	now := s.now()
	identities := s.lifecycle.List()
	view := dashboardView{
		Identities:   make([]identityView, 0, len(identities)),
		UpdatedAt:    now.Format("15:04 MST"),
		Build:        s.build,
		ClusterVault: s.clusterVaultEnabled(),
	}
	providers := make(map[string]providerSummary)
	for _, identity := range identities {
		item := toIdentityView(identity, now)
		view.Identities = append(view.Identities, item)
		view.Total++
		kind := identity.Provider.Provider
		if _, seen := providers[kind]; !seen && kind != "" {
			providers[kind] = providerSummary{Kind: kind, Label: providerLabel(kind), Mark: providerMark(kind), Scope: providerScope(identity)}
		}
		switch item.Urgency {
		case string(protocol.UrgencyHealthy):
			if item.RenewalHealth == string(protocol.HealthHealthy) {
				view.Healthy++
			}
		case string(protocol.UrgencyExpiring):
			view.Expiring++
		}
		if item.RenewalHealth != string(protocol.HealthHealthy) || item.Urgency == string(protocol.UrgencyOverdue) {
			view.Attention++
		}
	}
	for _, kind := range []string{"azure-entra", "aws-iam", "gcp-iam"} {
		if summary, ok := providers[kind]; ok {
			view.Providers = append(view.Providers, summary)
		}
	}
	view.Provision = s.provisionableProviders()
	// Advertise wired real adapters even before the first identity exists so
	// the footer always reflects what the demo is attached to. Explicit
	// provider descriptors (labels + public tenant scopes) win when the
	// configuration advertises them; otherwise fall back to the
	// feature-flag-derived summaries without identifiers.
	if descriptors := s.wiredProviderDescriptors(); len(descriptors) > 0 {
		for _, descriptor := range descriptors {
			if _, ok := providers[descriptor.Kind]; ok {
				continue
			}
			view.Providers = append(view.Providers, providerSummary{
				Kind: descriptor.Kind, Label: descriptor.Label, Mark: providerMark(descriptor.Kind), Scope: descriptor.Scope,
			})
		}
	} else {
		for _, candidate := range view.Provision {
			if _, ok := providers[candidate.Kind]; !ok {
				view.Providers = append(view.Providers, candidate)
			}
		}
	}
	view.LiveReal = len(view.Provision) > 0
	return view
}

// wiredProviderDescriptors returns the provider descriptors advertised by the
// wired configuration, or nil when it does not carry them; callers then keep
// the feature-flag fallback. The composition root passes config.Public as the
// configuration service; its Providers field lists the wired adapters with
// their explicit, non-secret tenant scopes when set. Reading the field here
// keeps the optional capability entirely consumer-side: no config-side
// accessor and no wiring change are required.
func (s *Server) wiredProviderDescriptors() []config.ProviderDescriptor {
	if s.configuration == nil {
		return nil
	}
	if public, ok := s.configuration.(config.Public); ok {
		return public.Providers
	}
	return nil
}

// clusterVaultEnabled reports whether the wired configuration advertises the
// in-cluster μVault as a credential delivery target.
func (s *Server) clusterVaultEnabled() bool {
	if s.configuration == nil {
		return false
	}
	for _, feature := range s.configuration.Configuration().Features {
		if feature == "vault:cluster" {
			return true
		}
	}
	return false
}

// provisionableProviders returns the providers whose live adapters support
// creating zero-permission identities, advertised by main via the
// "provision:<kind>" feature flag. Explicit provider descriptors, when
// available, contribute the authoritative label and public tenant scope.
func (s *Server) provisionableProviders() []providerSummary {
	if s.configuration == nil {
		return nil
	}
	cfg := s.configuration.Configuration()
	seen := make(map[string]bool)
	var out []providerSummary
	for _, feature := range cfg.Features {
		kind, ok := strings.CutPrefix(feature, "provision:")
		if !ok || seen[kind] {
			continue
		}
		seen[kind] = true
		out = append(out, providerSummary{
			Kind:  kind,
			Label: providerLabel(kind),
			Mark:  providerMark(kind),
			Scope: "real tenant, zero permissions",
		})
	}
	descriptors := s.wiredProviderDescriptors()
	if len(descriptors) == 0 {
		return out
	}
	byKind := make(map[string]config.ProviderDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byKind[descriptor.Kind] = descriptor
	}
	scoped := make([]providerSummary, 0, len(out))
	for _, summary := range out {
		if descriptor, ok := byKind[summary.Kind]; ok {
			summary.Label = descriptor.Label
			summary.Scope = descriptor.Scope
		}
		scoped = append(scoped, summary)
	}
	return scoped
}

type configurationPageView struct {
	protocol.Configuration
	IntegrationEnabled bool
	Requirements       protocol.AzureIntegrationRequirements
	Provision          []providerSummary
	Build              buildView
}

// buildView is the public, non-secret description of the source revision that
// produced the running binary; the page footers link the exact commit.
type buildView struct {
	Short string
	URL   string
	Dirty bool
}

// toBuildView resolves the build revision for rendering. It carries only a
// public commit id — never build secrets or private details.
func toBuildView() buildView {
	build := buildinfo.Current()
	return buildView{Short: build.Short(), URL: build.URL(), Dirty: build.Dirty}
}

// vaultReferenceName names the vault a credential copy lives in, honestly
// distinguishing the in-cluster μVault (detected by its service URL) from the
// provider-native vaults. The name is display copy only, never a secret.
func vaultReferenceName(vault *protocol.VaultReference, providerKind string) string {
	if vault != nil && strings.Contains(vault.URL, "mutandae-vault") {
		return "the cluster μVault vault"
	}
	return vaultLabel(providerKind)
}

type provisionView struct {
	Identity     identityView
	KeyID        string
	Secret       string
	Vault        *protocol.VaultReference
	VaultName    string
	Instructions string
	Dashboard    dashboardView
}

// provisionResultView is the compact dashboard fragment for a fresh identity:
// one-time secret, vault delivery status, and an out-of-band inventory refresh.
type provisionResultView struct {
	Identity  identityView
	KeyID     string
	Secret    string
	Vault     *protocol.VaultReference
	VaultName string
	Dashboard dashboardView
}

// useResultView is the activity-panel fragment for a vault-backed credential
// retrieval. It carries the secret value once; the audit trail records only
// the vault reference.
type useResultView struct {
	Identity  identityView
	KeyID     string
	Secret    string
	Vault     *protocol.VaultReference
	VaultName string
}

const demoPrefixWeb = "mutandae-demo-"

// dashboardView carries the multi-provider summary plus the identity inventory.
type dashboardView struct {
	Identities   []identityView
	Providers    []providerSummary
	Provision    []providerSummary
	LiveReal     bool
	Total        int
	Healthy      int
	Expiring     int
	Attention    int
	UpdatedAt    string
	Build        buildView
	ClusterVault bool
}

// providerSummary is a single provider adapter rendered in the dashboard.
type providerSummary struct {
	Kind  string
	Label string
	Mark  string
	Scope string
}

type identityView struct {
	ID                 string
	Name               string
	Provider           string
	ProviderKind       string
	ProviderMark       string
	Environment        string
	Owner              string
	Workload           string
	Criticality        string
	State              string
	StateLabel         string
	RenewalHealth      string
	Urgency            string
	UrgencyLabel       string
	UrgencyClass       string
	ExpiryLabel        string
	ExpiryRelative     string
	LastRotatedLabel   string
	VaultLabel         string
	VaultVersion       string
	CommonVaultLabel   string
	CommonVaultVersion string
	SearchText         string
}

type eventsView struct {
	Identity identityView
	Events   []protocol.LifecycleEvent
}

func urgency(identity protocol.MachineIdentity, now time.Time) protocol.Urgency {
	if identity.State == protocol.StateRetired {
		return protocol.UrgencyRetired
	}
	if !identity.ExpiresAt.After(now) {
		return protocol.UrgencyOverdue
	}
	if identity.ExpiresAt.Before(now.Add(30 * 24 * time.Hour)) {
		return protocol.UrgencyExpiring
	}
	return protocol.UrgencyHealthy
}

func toIdentityView(identity protocol.MachineIdentity, now time.Time) identityView {
	urg := urgency(identity, now)
	days := int(identity.ExpiresAt.Sub(now).Hours() / 24)
	if identity.ExpiresAt.After(now) && identity.ExpiresAt.Sub(now)%(24*time.Hour) != 0 {
		days++
	}
	base := identityView{
		ID: identity.ID, Name: identity.Name,
		Provider: providerLabel(identity.Provider.Provider), ProviderKind: identity.Provider.Provider,
		ProviderMark: providerMark(identity.Provider.Provider),
		Environment:  identity.Environment, Owner: identity.Ownership.Team, Workload: identity.Ownership.Service,
		Criticality: identity.Ownership.Criticality, State: string(identity.State),
		StateLabel: stateLabel(identity.State), RenewalHealth: string(identity.Health), Urgency: string(urg),
		UrgencyLabel: urgencyLabel(urg), UrgencyClass: string(urg),
		ExpiryLabel:      identity.ExpiresAt.Format("Jan 02, 2006"),
		LastRotatedLabel: lastRotatedLabel(identity.LastRotatedAt),
	}
	if days < 0 {
		base.ExpiryRelative = "Overdue by " + formatDays(-days)
	} else {
		relative := "Due today"
		if days == 1 {
			relative = "Due tomorrow"
		} else if days > 1 {
			relative = "Due in " + formatDays(days)
		}
		base.ExpiryRelative = relative
	}
	// Vault state comes from provider-neutral identity metadata recorded at
	// delivery time: names, URLs, and versions only — never secret material.
	base.VaultLabel = vaultLabel(identity.Provider.Provider)
	base.VaultVersion = identity.Metadata["vault_version"]
	// The cluster μVault delivery records its copy under the common_vault_*
	// metadata keys; render it alongside (or instead of) the native vault.
	if identity.Metadata["common_vault_url"] != "" || identity.Metadata["common_vault_secret"] != "" || identity.Metadata["common_vault_version"] != "" {
		base.CommonVaultLabel = "μVault (cluster)"
	}
	base.CommonVaultVersion = identity.Metadata["common_vault_version"]
	base.SearchText = strings.ToLower(strings.Join([]string{
		identity.Name, base.Provider, identity.Environment, base.Owner, base.Workload, base.Criticality,
	}, " "))
	return base
}

func providerLabel(kind string) string {
	switch kind {
	case "azure-entra":
		return "Azure / Entra ID"
	case "aws-iam":
		return "AWS IAM"
	case "gcp-iam":
		return "GCP IAM"
	default:
		if kind == "" {
			return "Unknown"
		}
		return kind
	}
}

// providerVaultLabel names the native vault behind each provider kind so the
// inventory and provision results can show where a credential lives.
func vaultLabel(kind string) string {
	switch kind {
	case "azure-entra":
		return "Key Vault"
	case "aws-iam":
		return "Secrets Manager"
	case "gcp-iam":
		return "Secret Manager"
	default:
		return "Vault"
	}
}

// providerMark is the compact avatar shown beside a provider in the inventory.
func providerMark(kind string) string {
	switch kind {
	case "azure-entra":
		return "Az"
	case "aws-iam":
		return "AW"
	case "gcp-iam":
		return "GC"
	default:
		return "?"
	}
}

// providerScope describes which provider namespace an identity lives in.
func providerScope(identity protocol.MachineIdentity) string {
	switch identity.Provider.Provider {
	case "azure-entra":
		return "tenant " + identity.Provider.TenantID
	case "aws-iam":
		return "account " + identity.Provider.AccountID
	case "gcp-iam":
		return "project " + identity.Provider.ProjectID
	default:
		return ""
	}
}

func stateLabel(state protocol.State) string {
	switch state {
	case protocol.StateRegistered:
		return "Registered"
	case protocol.StateRenewing:
		return "Renewing"
	case protocol.StateRetired:
		return "Retired"
	default:
		return "Active"
	}
}

func urgencyLabel(urgency protocol.Urgency) string {
	switch urgency {
	case protocol.UrgencyExpiring:
		return "Expiring soon"
	case protocol.UrgencyOverdue:
		return "Overdue"
	case protocol.UrgencyRetired:
		return "Retired"
	default:
		return "Healthy"
	}
}

func formatDays(days int) string {
	unit := "days"
	if days == 1 {
		unit = "day"
	}
	return strconvItoa(days) + " " + unit
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}

func lastRotatedLabel(value time.Time) string {
	if value.IsZero() {
		return "Never"
	}
	return value.Format("Jan 02, 2006")
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Printf("render %s: %v", name, err)
	}
}
