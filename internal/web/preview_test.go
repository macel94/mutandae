package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestHTMLRotationPreviewIsReadOnlyAndRequiresSecondMutation(t *testing.T) {
	server := testServer(t)
	handler := server.routes()
	before, ok := server.lifecycle.Get("payments-api")
	if !ok {
		t.Fatal("seeded identity is missing")
	}
	beforeEvents, _ := server.lifecycle.Events(before.ID)
	beforeRuns, _ := server.lifecycle.Runs(before.ID)

	form := url.Values{"dry_run": {"1"}}
	request := httptest.NewRequest(http.MethodPost, "/identities/payments-api/rotate", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("preview status = %d: %s", response.Code, response.Body.String())
	}
	for _, marker := range []string{"Dry-run plan", "graph.addPassword", "Confirm and rotate"} {
		if !strings.Contains(response.Body.String(), marker) {
			t.Errorf("preview omitted %q: %s", marker, response.Body.String())
		}
	}
	after, _ := server.lifecycle.Get(before.ID)
	afterEvents, _ := server.lifecycle.Events(before.ID)
	afterRuns, _ := server.lifecycle.Runs(before.ID)
	if after.Credential.KeyID != before.Credential.KeyID || after.State != before.State {
		t.Fatalf("preview changed identity: before=%+v after=%+v", before, after)
	}
	if len(afterEvents) != len(beforeEvents) || len(afterRuns) != len(beforeRuns) {
		t.Fatalf("preview changed audit state: events %d->%d runs %d->%d", len(beforeEvents), len(afterEvents), len(beforeRuns), len(afterRuns))
	}

	confirm := httptest.NewRecorder()
	handler.ServeHTTP(confirm, httptest.NewRequest(http.MethodPost, "/identities/payments-api/rotate", nil))
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm status = %d: %s", confirm.Code, confirm.Body.String())
	}
	mutated, _ := server.lifecycle.Get(before.ID)
	if mutated.Credential.KeyID == before.Credential.KeyID {
		t.Fatal("explicit confirmation did not perform the rotation")
	}
}

func TestHTMLRetirementPreviewDoesNotRetireUntilConfirm(t *testing.T) {
	server := testServer(t)
	handler := server.routes()

	form := url.Values{"dry_run": {"true"}}
	request := httptest.NewRequest(http.MethodPost, "/identities/payments-api/retire", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("retirement preview status = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Confirm and retire") {
		t.Fatal("retirement preview omitted explicit confirmation action")
	}
	identity, _ := server.lifecycle.Get("payments-api")
	if identity.State != protocol.StateActive {
		t.Fatalf("retirement preview changed state to %q", identity.State)
	}

	confirm := httptest.NewRecorder()
	handler.ServeHTTP(confirm, httptest.NewRequest(http.MethodPost, "/identities/payments-api/retire", nil))
	if confirm.Code != http.StatusOK {
		t.Fatalf("retirement confirmation status = %d: %s", confirm.Code, confirm.Body.String())
	}
	identity, _ = server.lifecycle.Get("payments-api")
	if identity.State != protocol.StateRetired {
		t.Fatalf("confirmed retirement state = %q", identity.State)
	}
}

func TestAPIDryRunReturnsPlanWithoutMutation(t *testing.T) {
	server := testServer(t)
	handler := server.routes()
	before, _ := server.lifecycle.Get("payments-api")
	beforeEvents, _ := server.lifecycle.Events(before.ID)
	beforeRuns, _ := server.lifecycle.Runs(before.ID)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/identities/payments-api/rotations", strings.NewReader(`{"dry_run":true}`))
	request.Header.Set("Content-Type", protocol.MediaType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("API preview status = %d: %s", response.Code, response.Body.String())
	}
	var payload protocol.RotateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode API preview: %v", err)
	}
	if payload.Plan == nil || !payload.Plan.DryRun || len(payload.Plan.Operations) == 0 {
		t.Fatalf("API preview plan = %+v", payload.Plan)
	}
	if payload.Rotation.Status != "" {
		t.Fatalf("API preview returned an execution status %q", payload.Rotation.Status)
	}
	identity, _ := server.lifecycle.Get(before.ID)
	afterEvents, _ := server.lifecycle.Events(before.ID)
	afterRuns, _ := server.lifecycle.Runs(before.ID)
	if identity.Credential.KeyID != before.Credential.KeyID || len(afterEvents) != len(beforeEvents) || len(afterRuns) != len(beforeRuns) {
		t.Fatal("API preview mutated identity or lifecycle state")
	}
}
