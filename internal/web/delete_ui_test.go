package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// retireViaAPI retires one seeded identity through the protocol so delete
// tests exercise the real handler chain, not a shortcut.
func retireViaAPI(t *testing.T, handler http.Handler, id string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identities/"+id+"/retire", strings.NewReader(`{"confirm":true}`))
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retire %s status = %d, want 200: %s", id, recorder.Code, recorder.Body.String())
	}
}

func TestDeleteEndpointRequiresConfirmation(t *testing.T) {
	handler := testHandler(t)
	retireViaAPI(t, handler, "payments-api")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/identities/payments-api", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("delete without confirm status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	var failure protocol.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode failure envelope: %v", err)
	}
	if failure.Error.Code != protocol.ErrCodeInvalidRequest {
		t.Fatalf("error = %+v, want invalid_request", failure.Error)
	}
}

func TestDeleteEndpointPurgesRetiredIdentityAndReturnsEvidence(t *testing.T) {
	handler := testHandler(t)
	retireViaAPI(t, handler, "payments-api")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/identities/payments-api", strings.NewReader(`{"confirm":true,"reason":"decommission completely"}`))
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response protocol.DeleteResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !response.Deleted || response.Identity.State != protocol.StateRetired {
		t.Fatalf("response = (deleted=%v state=%s), want the final retired identity", response.Deleted, response.Identity.State)
	}
	if len(response.Events) == 0 || response.Events[len(response.Events)-1].Type != protocol.EventIdentityDeleted {
		t.Fatal("the delete response must end with the terminal identity.deleted event")
	}

	// The purged identity is gone from the inventory and from the API, and a
	// second delete reports not-found.
	if body := dashboardBody(t, handler, "/"); strings.Contains(body, "payments-api") {
		t.Error("the dashboard still lists the deleted identity")
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/identities/payments-api", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("inspect after delete status = %d, want 404", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/identities/payments-api", strings.NewReader(`{"confirm":true}`)))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", recorder.Code)
	}
}

func TestDeleteEndpointRejectsActiveIdentitiesWithConflict(t *testing.T) {
	handler := testHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/identities/payments-api", strings.NewReader(`{"confirm":true}`)))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("delete of an active identity status = %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
	var failure protocol.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode failure envelope: %v", err)
	}
	if failure.Error.Code != protocol.ErrCodeConflict {
		t.Fatalf("error = %+v, want conflict", failure.Error)
	}
}

func TestDeleteEndpointUnknownIdentityIsNotFound(t *testing.T) {
	handler := testHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/identities/ghost", strings.NewReader(`{"confirm":true}`)))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("delete unknown status = %d, want 404", recorder.Code)
	}
}

func TestDiscoveryAdvertisesDelete(t *testing.T) {
	handler := testHandler(t)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", recorder.Code)
	}
	var index protocol.DiscoveryIndex
	if err := json.Unmarshal(recorder.Body.Bytes(), &index); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	for _, resource := range index.Resources {
		if resource.Rel == "delete" {
			if resource.Method != http.MethodDelete || resource.HREF != "/api/v1/identities/{id}" {
				t.Fatalf("delete discovery entry = %+v", resource)
			}
			return
		}
	}
	t.Error("discovery does not advertise the delete operation")
}

func TestBrowserDeletePurgesAndRendersFinalEvidence(t *testing.T) {
	handler := testHandler(t)
	retireViaAPI(t, handler, "payments-api")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/identities/payments-api", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("browser delete status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Permanently deleted") || !strings.Contains(body, "identity.deleted") {
		t.Error("the delete fragment must present the terminal evidence")
	}
	if !strings.Contains(body, `hx-swap-oob="true"`) {
		t.Error("the delete fragment must refresh the inventory out-of-band")
	}
	if body := dashboardBody(t, handler, "/"); strings.Contains(body, "payments-api") {
		t.Error("the dashboard still lists the deleted identity")
	}
}

func TestDashboardShowsDeleteOnlyOnRetiredRows(t *testing.T) {
	handler := testHandler(t)
	retireViaAPI(t, handler, "payments-api")

	body := dashboardBody(t, handler, "/")
	if !strings.Contains(body, `hx-delete="/identities/payments-api"`) {
		t.Error("retired rows must offer the permanent delete action")
	}
	for _, marker := range []string{"hx-post=\"/identities/payments-api/rotate\"", "hx-post=\"/identities/payments-api/retire\""} {
		if strings.Contains(body, marker) {
			t.Errorf("retired rows must not offer %s", marker)
		}
	}
	// Active rows keep the lifecycle actions and never the delete button.
	if !strings.Contains(body, `hx-post="/identities/data-pipeline/rotate"`) {
		t.Error("active rows lost their rotate action")
	}
	if strings.Count(body, "hx-delete=") != 1 {
		t.Errorf("delete action count = %d, want exactly one (the retired row)", strings.Count(body, "hx-delete="))
	}
}

// rowAround returns the full table row containing the given marker.
func rowAround(t *testing.T, body, marker string) string {
	t.Helper()
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found", marker)
	}
	start := strings.LastIndex(body[:idx], "<tr ")
	end := strings.Index(body[idx:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("malformed row around %q", marker)
	}
	return body[start : idx+end]
}

func TestRetiredRowsShowRetirementDateInsteadOfRenewalDeadline(t *testing.T) {
	handler := testHandler(t)
	retireViaAPI(t, handler, "payments-api")

	body := dashboardBody(t, handler, "/")
	row := rowAround(t, body, `hx-delete="/identities/payments-api"`)
	expiry := expiryCellOf(t, row)
	if strings.Contains(expiry, "Due in") || strings.Contains(expiry, "Overdue by") {
		t.Errorf("retired row still shows a renewal deadline: %q", expiry)
	}
	if !strings.Contains(expiry, "Retired") {
		t.Errorf("retired row expiry = %q, want the retirement framing", expiry)
	}
	if !strings.Contains(expiry, "no longer applies") {
		t.Errorf("retired row expiry tooltip = %q, want the explanation", expiry)
	}
	// Active rows keep the renewal framing.
	if active := rowAround(t, body, `hx-post="/identities/data-pipeline/rotate"`); !strings.Contains(expiryCellOf(t, active), "Due in") {
		t.Error("active rows lost the renewal deadline framing")
	}
}

func expiryCellOf(t *testing.T, row string) string {
	t.Helper()
	start := strings.Index(row, `<div class="expiry-cell"`)
	if start < 0 {
		t.Fatal("row has no expiry cell")
	}
	end := strings.Index(row[start:], "</div>")
	return row[start : start+end]
}
