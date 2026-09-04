package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// previewView is the provider-neutral HTML representation of a dry-run plan.
// Action is deliberately limited to the existing lifecycle form routes; the
// confirmation form never carries a dry_run field, so applying it is an
// explicit second request.
type previewView struct {
	Identity identityView
	Plan     protocol.Plan
	Action   string
}

// isDryRunForm recognizes the HTML form spelling for a read-only preview. The
// JSON API uses a real boolean and is decoded by encoding/json instead.
func isDryRunForm(r *http.Request) bool {
	value := strings.ToLower(strings.TrimSpace(r.PostFormValue("dry_run")))
	return value == "1" || value == "true" || value == "on" || value == "yes"
}

// previewRotation is also registered as /rotate/preview so callers that want
// an explicit preview endpoint do not need to construct a form field. The
// ordinary /rotate handler delegates here when dry_run=1 is posted.
func (s *Server) previewRotation(w http.ResponseWriter, r *http.Request) {
	resp, err := s.lifecycle.Rotate(r.Context(), protocol.RotateRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
		Reason:      "operator requested a rotation preview",
		DryRun:      true,
	}, s.now())
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	if resp.Plan == nil {
		s.writeError(w, errors.New("rotation preview did not return a plan"), http.StatusInternalServerError)
		return
	}
	s.render(w, "preview-result", previewView{
		Identity: toIdentityView(resp.Identity, s.now()),
		Plan:     *resp.Plan,
		Action:   "rotate",
	})
}

// previewRetirement renders a read-only retirement plan. Retirement's ordinary
// HTML handler delegates here for dry_run=1; the confirm button posts to the
// existing /retire route with confirm=1 and no dry_run field.
func (s *Server) previewRetirement(w http.ResponseWriter, r *http.Request) {
	resp, err := s.lifecycle.Retire(r.Context(), protocol.RetireRequest{
		ID:          r.PathValue("id"),
		RequestedBy: operatorOrDefault(r),
		Reason:      "operator requested a retirement preview",
		DryRun:      true,
	}, s.now())
	if err != nil {
		s.writeError(w, err, http.StatusConflict)
		return
	}
	if resp.Plan == nil {
		s.writeError(w, errors.New("retirement preview did not return a plan"), http.StatusInternalServerError)
		return
	}
	s.render(w, "preview-result", previewView{
		Identity: toIdentityView(resp.Identity, s.now()),
		Plan:     *resp.Plan,
		Action:   "retire",
	})
}
