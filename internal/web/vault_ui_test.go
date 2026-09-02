package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// provisioningConfiguration advertises one real provisioning target and its
// vault so the dashboard renders the New identity control.
type provisioningConfiguration struct{}

func (provisioningConfiguration) Configuration() protocol.Configuration {
	return protocol.Configuration{
		Service: "mutandae-control-plane", ProtocolVersion: protocol.Version,
		MediaType: protocol.MediaType, Environment: "live",
		Provider: "aws-iam (real)", Persistence: "in-memory",
		ReadOnly: false, Features: []string{"provision:aws-iam", "vault:aws-iam"}, UpdatedAt: testNow(),
	}
}

func newProvisioningServer(t *testing.T) http.Handler {
	t.Helper()
	handler, err := NewServer(Dependencies{
		Lifecycle:     &fakeLifecycle{},
		Configuration: provisioningConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return handler
}

func TestDashboardRendersNewIdentityControlMoreThanOnce(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	defer resp.Body.Close()
	raw := readAll(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.StatusCode)
	}
	forms := strings.Count(raw, `hx-post="/identities/provision"`)
	if forms < 2 {
		t.Fatalf("New identity control rendered %d times on the dashboard, want at least 2 (hero + inventory)", forms)
	}
	if !strings.Contains(raw, `value="aws-iam"`) {
		t.Fatal("identity type dropdown is missing the aws-iam option")
	}
	if !strings.Contains(raw, `id="provision-slot"`) {
		t.Fatal("dashboard is missing the provision result slot")
	}
}

func TestProvisionAcceptsFormValueAndRendersVaultSlotFragment(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	form := url.Values{"provider": {"aws-iam"}}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/identities/provision", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Target", "provision-slot")
	req.Header.Set("HX-Request", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	defer resp.Body.Close()
	raw := readAll(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("provision status = %d body %s", resp.StatusCode, raw)
	}
	if !strings.Contains(raw, "mutandae-demo-abc1") {
		t.Fatal("provision fragment does not show the provisioned identity")
	}
	if !strings.Contains(raw, "hx-swap-oob") {
		t.Fatal("dashboard fragment must refresh the inventory out-of-band")
	}
	if !strings.Contains(raw, "identity-table") {
		t.Fatal("dashboard fragment must embed the identity table template")
	}
}

func TestProvisionFragmentReportsMissingVaultCopy(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	form := url.Values{"provider": {"aws-iam"}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/identities/provision", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Target", "provision-slot")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	defer resp.Body.Close()
	raw := readAll(t, resp.Body)
	// The fake lifecycle carries no vault reference, so the fragment must say
	// so instead of pretending a copy exists.
	if !strings.Contains(raw, "No vault copy") {
		t.Fatal("provision fragment must honestly report a missing vault delivery")
	}
}

func TestUseRouteRendersAuditedRetrievalFragment(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// Provision first so the fake service holds the identity.
	provisionResp, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", strings.NewReader(`{"provider":"aws-iam"}`))
	if err != nil {
		t.Fatalf("api provision: %v", err)
	}
	_ = provisionResp.Body.Close()

	resp, err := http.Post(server.URL+"/identities/prov-1/use", "text/plain", nil)
	if err != nil {
		t.Fatalf("use: %v", err)
	}
	defer resp.Body.Close()
	raw := readAll(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("use status = %d body %s", resp.StatusCode, raw)
	}
	if !strings.Contains(raw, "demo-secret") {
		t.Fatal("use fragment did not return the vault secret")
	}
	if !strings.Contains(raw, "credential.used") {
		t.Fatal("use fragment must disclose that the retrieval is audited")
	}
	if !strings.Contains(raw, "mutandae-demo-abc1") {
		t.Fatal("use fragment must name the identity")
	}
}

func TestAPIUseReturnsVersionedEnvelope(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// Provision first so the fake service holds the identity.
	provisionResp, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", strings.NewReader(`{"provider":"aws-iam"}`))
	if err != nil {
		t.Fatalf("api provision: %v", err)
	}
	_ = provisionResp.Body.Close()
	if provisionResp.StatusCode != http.StatusCreated {
		t.Fatalf("api provision status = %d", provisionResp.StatusCode)
	}

	resp, err := http.Post(server.URL+"/api/v1/identities/prov-1/use", "application/json", strings.NewReader(`{"requested_by":"visitor"}`))
	if err != nil {
		t.Fatalf("api use: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api use status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != protocol.ContentType {
		t.Fatalf("api use content type = %q", got)
	}
	raw := readAll(t, resp.Body)
	for _, want := range []string{`"api_version":"v1"`, `"secret":"demo-secret"`, `"secret_name":"mutandae-demo-abc1"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("api use response missing %s: %s", want, raw)
		}
	}
}

func TestAPIUseNotFoundIs404(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Post(server.URL+"/api/v1/identities/missing/use", "application/json", nil)
	if err != nil {
		t.Fatalf("api use: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("api use status = %d, want 404", resp.StatusCode)
	}
}

func TestDashboardWithoutProvisioningHasNoNewIdentityControl(t *testing.T) {
	handler, err := NewServer(Dependencies{
		Lifecycle:     &fakeLifecycle{},
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	defer resp.Body.Close()
	raw := readAll(t, resp.Body)
	if strings.Contains(raw, `hx-post="/identities/provision"`) {
		t.Fatal("New identity control must not render without provisionable providers")
	}
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	var builder strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			builder.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return builder.String()
}
