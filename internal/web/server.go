package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

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
}

// Clock makes time-dependent rendering and mutations deterministic in tests.
type Clock func() time.Time

// Logger is intentionally smaller than a concrete logging implementation.
type Logger interface {
	Printf(format string, args ...any)
}

type Dependencies struct {
	Lifecycle LifecycleService
	Clock     Clock
	Logger    Logger
}

type Server struct {
	lifecycle LifecycleService
	templates *template.Template
	static    fs.FS
	now       Clock
	logger    Logger
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
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	return &Server{
		lifecycle: deps.Lifecycle,
		templates: templates,
		static:    static,
		now:       deps.Clock,
		logger:    deps.Logger,
	}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	// Server-rendered frontend (HTMX + Alpine).
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /partials/identities", s.identityList)
	mux.HandleFunc("GET /identities/{id}/events", s.identityEvents)
	mux.HandleFunc("POST /identities/{id}/rotate", s.rotate)
	mux.HandleFunc("POST /identities/{id}/retire", s.retire)
	// Protocol JSON API (versioned).
	mux.HandleFunc("GET /api/v1/", s.apiRoot)
	mux.HandleFunc("GET /api/v1/identities", s.apiList)
	mux.HandleFunc("POST /api/v1/identities", s.apiRegister)
	mux.HandleFunc("GET /api/v1/identities/{id}", s.apiInspect)
	mux.HandleFunc("POST /api/v1/identities/{id}/rotations", s.apiRotate)
	mux.HandleFunc("POST /api/v1/identities/{id}/retire", s.apiRetire)
	// Health probes.
	mux.HandleFunc("GET /livez", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.static))))
	return mux
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index", s.dashboardView())
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

// --- Protocol JSON API ---

func (s *Server) apiRoot(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, protocol.DiscoveryIndex{
		APIVersion: protocol.Version,
		Service:    "mutandae-control-plane",
		MediaType:  protocol.MediaType,
		Resources: []protocol.DiscoveryResource{
			{Rel: "identities", Method: http.MethodGet, HREF: "/api/v1/identities", Envelope: "list"},
			{Rel: "identity", Method: http.MethodGet, HREF: "/api/v1/identities/{id}", Envelope: "inspect"},
			{Rel: "register", Method: http.MethodPost, HREF: "/api/v1/identities", Envelope: "register"},
			{Rel: "rotate", Method: http.MethodPost, HREF: "/api/v1/identities/{id}/rotations", Envelope: "rotate"},
			{Rel: "retire", Method: http.MethodPost, HREF: "/api/v1/identities/{id}/retire", Envelope: "retire"},
		},
	})
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
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Printf("encode protocol payload: %v", err)
	}
}

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
		Identities: make([]identityView, 0, len(identities)),
		UpdatedAt:  now.Format("15:04 MST"),
	}
	for _, identity := range identities {
		item := toIdentityView(identity, now)
		view.Identities = append(view.Identities, item)
		view.Total++
		if view.TenantID == "" && identity.Provider.TenantID != "" {
			view.TenantID = identity.Provider.TenantID
		}
		if view.ProviderLabel == "" && identity.Provider.Provider != "" {
			view.Provider = identity.Provider.Provider
			view.ProviderLabel = providerLabel(identity.Provider.Provider)
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
	return view
}

type dashboardView struct {
	Identities    []identityView
	Total         int
	Healthy       int
	Expiring      int
	Attention     int
	UpdatedAt     string
	Provider      string
	ProviderLabel string
	TenantID      string
}

type identityView struct {
	ID               string
	Name             string
	Provider         string
	ProviderKind     string
	Environment      string
	Owner            string
	Workload         string
	Criticality      string
	State            string
	StateLabel       string
	RenewalHealth    string
	Urgency          string
	UrgencyLabel     string
	UrgencyClass     string
	ExpiryLabel      string
	ExpiryRelative   string
	LastRotatedLabel string
	SearchText       string
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
		Environment: identity.Environment, Owner: identity.Ownership.Team, Workload: identity.Ownership.Service,
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
