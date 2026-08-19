package web

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// LifecycleService is the web layer's small consumer-defined boundary. The
// production implementation is lifecycle.Store; tests and future adapters can
// provide a narrower fake or a remote implementation without changing handlers.
type LifecycleService interface {
	List() []lifecycle.Identity
	Get(id string) (lifecycle.Identity, bool)
	Events(id string) ([]lifecycle.Event, bool)
	Rotate(id string, now time.Time) (lifecycle.Identity, error)
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
		"eventClass": func(outcome string) string {
			if outcome == "success" {
				return "event-success"
			}
			if outcome == "attention" {
				return "event-attention"
			}
			return "event-progress"
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
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /partials/identities", s.identityList)
	mux.HandleFunc("GET /identities/{id}/events", s.identityEvents)
	mux.HandleFunc("POST /identities/{id}/rotate", s.rotate)
	mux.HandleFunc("GET /api/identities", s.apiIdentities)
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
	_, err := s.lifecycle.Rotate(r.PathValue("id"), s.now())
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, lifecycle.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.identityList(w, r)
}

func (s *Server) apiIdentities(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	identities := s.lifecycle.List()
	response := make([]apiIdentity, 0, len(identities))
	for _, identity := range identities {
		view := toIdentityView(identity, now)
		response = append(response, apiIdentity{
			ID: view.ID, Name: view.Name, Provider: view.Provider, Environment: view.Environment,
			Owner: view.Owner, Workload: view.Workload, Criticality: view.Criticality, State: identity.State,
			RenewalHealth: identity.RenewalHealth, Urgency: identity.Urgency(now), ExpiresAt: identity.ExpiresAt,
			LastRotatedAt: identity.LastRotatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Printf("encode identities: %v", err)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
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
		switch item.Urgency {
		case string(lifecycle.UrgencyHealthy):
			if item.RenewalHealth == string(lifecycle.RenewalHealthy) {
				view.Healthy++
			}
		case string(lifecycle.UrgencyExpiring):
			view.Expiring++
		}
		if item.RenewalHealth != string(lifecycle.RenewalHealthy) || item.Urgency == string(lifecycle.UrgencyOverdue) {
			view.Attention++
		}
	}
	return view
}

type dashboardView struct {
	Identities []identityView
	Total      int
	Healthy    int
	Expiring   int
	Attention  int
	UpdatedAt  string
}

type identityView struct {
	ID               string
	Name             string
	Provider         string
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
	Events   []lifecycle.Event
}

type apiIdentity struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	Provider      string                  `json:"provider"`
	Environment   string                  `json:"environment"`
	Owner         string                  `json:"owner"`
	Workload      string                  `json:"workload"`
	Criticality   string                  `json:"criticality"`
	State         lifecycle.State         `json:"state"`
	RenewalHealth lifecycle.RenewalHealth `json:"renewal_health"`
	Urgency       lifecycle.Urgency       `json:"urgency"`
	ExpiresAt     time.Time               `json:"expires_at"`
	LastRotatedAt time.Time               `json:"last_rotated_at"`
}

func toIdentityView(identity lifecycle.Identity, now time.Time) identityView {
	urgency := identity.Urgency(now)
	days := int(identity.ExpiresAt.Sub(now).Hours() / 24)
	if identity.ExpiresAt.After(now) && identity.ExpiresAt.Sub(now)%(24*time.Hour) != 0 {
		days++
	}
	if days < 0 {
		daysAbs := -days
		return identityView{
			ID: identity.ID, Name: identity.Name, Provider: identity.Provider, Environment: identity.Environment,
			Owner: identity.Owner, Workload: identity.Workload, Criticality: identity.Criticality, State: string(identity.State),
			StateLabel: stateLabel(identity.State), RenewalHealth: string(identity.RenewalHealth), Urgency: string(urgency),
			UrgencyLabel: urgencyLabel(urgency), UrgencyClass: string(urgency), ExpiryLabel: identity.ExpiresAt.Format("Jan 02, 2006"),
			ExpiryRelative: "Overdue by " + formatDays(daysAbs), LastRotatedLabel: lastRotatedLabel(identity.LastRotatedAt),
			SearchText: searchText(identity),
		}
	}
	relative := "Due today"
	if days == 1 {
		relative = "Due tomorrow"
	} else if days > 1 {
		relative = "Due in " + formatDays(days)
	}
	return identityView{
		ID: identity.ID, Name: identity.Name, Provider: identity.Provider, Environment: identity.Environment,
		Owner: identity.Owner, Workload: identity.Workload, Criticality: identity.Criticality, State: string(identity.State),
		StateLabel: stateLabel(identity.State), RenewalHealth: string(identity.RenewalHealth), Urgency: string(urgency),
		UrgencyLabel: urgencyLabel(urgency), UrgencyClass: string(urgency), ExpiryLabel: identity.ExpiresAt.Format("Jan 02, 2006"),
		ExpiryRelative: relative, LastRotatedLabel: lastRotatedLabel(identity.LastRotatedAt), SearchText: searchText(identity),
	}
}

func stateLabel(state lifecycle.State) string {
	switch state {
	case lifecycle.StateRegistered:
		return "Registered"
	case lifecycle.StateRenewing:
		return "Renewing"
	case lifecycle.StateRetired:
		return "Retired"
	default:
		return "Active"
	}
}

func urgencyLabel(urgency lifecycle.Urgency) string {
	switch urgency {
	case lifecycle.UrgencyExpiring:
		return "Expiring soon"
	case lifecycle.UrgencyOverdue:
		return "Overdue"
	case lifecycle.UrgencyRetired:
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
	return strings.TrimSpace(strings.Join([]string{fmtInt(days), unit}, " "))
}

func fmtInt(value int) string {
	// The demo only needs small day counts; keeping formatting local avoids a
	// third-party dependency for a single integer.
	return strconvItoa(value)
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

func searchText(identity lifecycle.Identity) string {
	return strings.ToLower(strings.Join([]string{
		identity.Name, identity.Provider, identity.Environment, identity.Owner, identity.Workload, identity.Criticality,
	}, " "))
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Printf("render %s: %v", name, err)
	}
}
