package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/buildinfo"
	"github.com/mutandae/mutandae/internal/config"
	"github.com/mutandae/mutandae/pkg/protocol"
)

// dashboardBody fetches a rendered page body through the full handler stack.
func dashboardBody(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s status = %d, want 200: %s", path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func TestDashboardAndConfigurationAreAlpineFree(t *testing.T) {
	handler := testHandler(t)
	for _, path := range []string{"/", "/configuration", "/partials/identities"} {
		body := dashboardBody(t, handler, path)
		for _, forbidden := range []string{"alpinejs", "x-data", "x-show", "x-on:", "x-model", "x-bind", "x-cloak"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s still references %q; the demo must stay framework-free", path, forbidden)
			}
		}
	}
}

func TestDashboardRendersAuditModalMarkup(t *testing.T) {
	body := dashboardBody(t, testHandler(t), "/")
	for _, expected := range []string{
		`<div class="modal-backdrop" id="audit-modal" hidden>`,
		`role="dialog"`,
		`aria-modal="true"`,
		`aria-labelledby="audit-modal-title"`,
		`<p class="modal-heading">Audit trail</p>`,
		`class="modal-close" type="button" aria-label="Close audit trail"`,
		`<div class="modal-body" id="audit-modal-content"></div>`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("dashboard modal markup missing %q", expected)
		}
	}
}

func TestDashboardNavLinksToProtocolSection(t *testing.T) {
	body := dashboardBody(t, testHandler(t), "/")
	if !strings.Contains(body, `<a href="#protocol">Protocol</a>`) {
		t.Error("topnav does not link the #protocol section")
	}
	if !strings.Contains(body, `<section class="protocol-explainer panel" id="protocol" aria-labelledby="protocol-title">`) {
		t.Error("dashboard is missing the protocol explainer section")
	}
	for _, expected := range []string{
		"What is the μTandae Protocol?",
		"registered → active → renewing → retired",
		"identity.discovered",
		"identity.registered",
		"rotation.*",
		"credential.delivered",
		"credential.revoked",
		"identity.retired",
		"application/vnd.mutandae.v1+json",
		"Azure/Entra ID, AWS IAM, and GCP IAM adapters",
		"curl /api/v1/",
		"https://github.com/macel94/mutandae/blob/main/docs/protocol.md",
		"https://github.com/macel94/mutandae/blob/main/pkg/protocol/schema/mutandae.v1.json",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("protocol explainer does not contain %q", expected)
		}
	}
}

func TestInventoryActionsTargetAuditModalContent(t *testing.T) {
	body := dashboardBody(t, testHandler(t), "/")
	if !strings.Contains(body, `hx-get="/identities/payments-api/events" hx-target="#audit-modal-content" hx-swap="innerHTML"`) {
		t.Error("inspect button must swap its events fragment into #audit-modal-content")
	}
	if !strings.Contains(body, `hx-target="#identity-list" hx-swap="outerHTML">Rotate`) {
		t.Error("rotate button must keep refreshing #identity-list")
	}
	if !strings.Contains(body, `hx-target="#identity-list" hx-swap="outerHTML" hx-confirm=`) {
		t.Error("retire button must keep refreshing #identity-list")
	}
	// The simulator carries no vault copy, so the use button stays hidden.
	if strings.Contains(body, "/identities/payments-api/use") {
		t.Error("use button must not render without a vault version")
	}
}

func TestEventsFragmentCarriesModalTitle(t *testing.T) {
	body := dashboardBody(t, testHandler(t), "/identities/payments-api/events")
	if !strings.Contains(body, `<h2 id="audit-modal-title">payments-api</h2>`) {
		t.Error("events fragment must carry the modal title for aria-labelledby")
	}
}

func TestStaticAppJSServed(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("app.js status = %d, want 200", recorder.Code)
	}
	contentType := recorder.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/javascript") && !strings.HasPrefix(contentType, "application/javascript") {
		t.Fatalf("app.js content type = %q, want JavaScript", contentType)
	}
	body := recorder.Body.String()
	for _, expected := range []string{
		"function filterRows",
		"function openModal",
		"function closeModal",
		"htmx:afterSwap",
		"audit-modal-content",
		"modal-open",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("app.js does not contain %q", expected)
		}
	}
}

func TestFooterBuildLinkReflectsRevision(t *testing.T) {
	previous := buildinfo.Revision
	t.Cleanup(func() { buildinfo.Revision = previous })

	buildinfo.Revision = "abc123def4567890abc123def4567890abc123de"
	handler := testHandler(t)
	for _, path := range []string{"/", "/configuration"} {
		body := dashboardBody(t, handler, path)
		if !strings.Contains(body, `class="footer-build"`) {
			t.Errorf("%s does not render the build link", path)
		}
		if !strings.Contains(body, `href="https://github.com/macel94/mutandae/commit/abc123def4567890abc123def4567890abc123de"`) {
			t.Errorf("%s build link does not point at the commit page", path)
		}
		if !strings.Contains(body, "Built from abc123d") {
			t.Errorf("%s does not name the short revision", path)
		}
	}

	// Without the injected revision the page must reflect buildinfo.Current():
	// a VCS-stamped test binary keeps linking its own revision, a stampless
	// build hides the link entirely. The revision is resolved at server
	// construction, so a fresh handler is built for this phase.
	buildinfo.Revision = ""
	current := buildinfo.Current()
	handler = testHandler(t)
	for _, path := range []string{"/", "/configuration"} {
		body := dashboardBody(t, handler, path)
		if current.URL() == "" {
			if strings.Contains(body, "footer-build") {
				t.Errorf("%s renders a build link with no known revision", path)
			}
			continue
		}
		if !strings.Contains(body, `href="`+current.URL()+`"`) {
			t.Errorf("%s does not link the VCS revision the binary was built from", path)
		}
	}
}

func TestFooterBuildLinkMarksDirtyTrees(t *testing.T) {
	server := testServer(t)
	server.build = buildView{Short: "deadbee", URL: "https://github.com/macel94/mutandae/commit/deadbee", Dirty: true}
	handler := server.routes()
	body := dashboardBody(t, handler, "/")
	if !strings.Contains(body, "Built from deadbee ↗ · modified") {
		t.Error("dirty tree must be labelled in the build link")
	}
}

func TestProviderDescriptorsDriveFooterScopes(t *testing.T) {
	handler, err := NewServer(Dependencies{
		Lifecycle: &fakeLifecycle{},
		Configuration: config.Public{
			Environment: "preview",
			Clock:       func() time.Time { return testNow() },
			Providers: []config.ProviderDescriptor{
				{Kind: "azure-entra", Label: "Azure / Entra ID", Scope: "tenant ee37cc75-1111-2222"},
				{Kind: "aws-iam", Label: "AWS IAM", Scope: "account 572030963802"},
				{Kind: "gcp-iam", Label: "GCP IAM", Scope: "project mutandae-demo"},
			},
		},
		Clock:  func() time.Time { return testNow() },
		Logger: testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := dashboardBody(t, handler, "/")
	for _, expected := range []string{
		// Scope arrives as pre-built text ("tenant …", "account …", "project …")
		// and must be rendered verbatim next to the descriptor label.
		"Azure / Entra ID</strong> · tenant ee37cc75-1111-2222",
		"AWS IAM</strong> · account 572030963802",
		"GCP IAM</strong> · project mutandae-demo",
		"tenant ee37cc75-1111-2222",
		"account 572030963802",
		"project mutandae-demo",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("footer does not name the descriptor scope %q", expected)
		}
	}
}

// TestDescriptorOverridesIdentityDerivedScope pins the authority order for
// footer scopes: identities created before the descriptors existed may not
// carry the tenant identifier, so the descriptor scope must win over the
// identity-derived "tenant <empty>" summary.
func TestDescriptorOverridesIdentityDerivedScope(t *testing.T) {
	identity := protocol.MachineIdentity{
		ID:          "legacy-azure",
		Name:        "mutandae-demo-legacy",
		Environment: "demo",
		Provider:    protocol.ProviderBinding{Provider: "azure-entra", ProviderID: "object-id-1", ObjectID: "object-id-1"},
		Ownership:   protocol.Ownership{Team: "Demo", Service: "legacy"},
		Policy:      protocol.LifecyclePolicy{RenewalPeriod: "P90D"},
		State:       protocol.StateActive,
		Health:      protocol.HealthHealthy,
		ExpiresAt:   testNow().Add(60 * 24 * time.Hour),
		CreatedAt:   testNow(),
		UpdatedAt:   testNow(),
	}
	lifecycle := &fakeLifecycle{identities: []protocol.MachineIdentity{identity}}
	handler, err := NewServer(Dependencies{
		Lifecycle: lifecycle,
		Configuration: config.Public{
			Environment: "live",
			Clock:       func() time.Time { return testNow() },
			Providers: []config.ProviderDescriptor{
				{Kind: "azure-entra", Label: "Azure / Entra ID", Scope: "tenant ee37cc75-5268-4985-8325-7708e8b739ab"},
			},
		},
		Clock:  func() time.Time { return testNow() },
		Logger: testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := dashboardBody(t, handler, "/")
	if !strings.Contains(body, "Azure / Entra ID</strong> · tenant ee37cc75-5268-4985-8325-7708e8b739ab") {
		t.Error("descriptor scope must override the identity-derived empty tenant scope")
	}
	if strings.Contains(body, "· tenant </span>") {
		t.Error("footer must never render an empty tenant scope")
	}
}

func TestProviderScopeFallsBackWithoutDescriptors(t *testing.T) {
	handler, err := NewServer(Dependencies{
		Lifecycle: &fakeLifecycle{},
		Configuration: config.Public{
			Environment: "preview",
			Clock:       func() time.Time { return testNow() },
			Features:    []string{"provision:aws-iam"},
		},
		Clock:  func() time.Time { return testNow() },
		Logger: testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := dashboardBody(t, handler, "/")
	if !strings.Contains(body, "<strong>AWS IAM</strong> · real tenant, zero permissions") {
		t.Error("footer must keep the feature-flag fallback text without descriptors")
	}
}

func TestClusterVaultFeatureAddsFooterLine(t *testing.T) {
	withClusterVault, err := NewServer(Dependencies{
		Lifecycle: &fakeLifecycle{},
		Configuration: config.Public{
			Environment: "preview",
			Clock:       func() time.Time { return testNow() },
			Features:    []string{"vault:cluster"},
		},
		Clock:  func() time.Time { return testNow() },
		Logger: testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := dashboardBody(t, withClusterVault, "/")
	if !strings.Contains(body, "Cluster vault: μVault (KV v2) · demo credentials persist in the cluster") {
		t.Error("footer must advertise the cluster vault when the feature flag is wired")
	}

	without := dashboardBody(t, testHandler(t), "/")
	if strings.Contains(without, "Cluster vault:") {
		t.Error("footer must not advertise a cluster vault without the feature flag")
	}
}

func TestVaultCellRendersClusterVaultCopy(t *testing.T) {
	fake := &fakeLifecycle{identities: []protocol.MachineIdentity{
		{
			ID: "both-vaults", Name: "both-vaults", Environment: "production",
			Provider:  protocol.ProviderBinding{Provider: "aws-iam", ProviderID: "obj-1", AccountID: "123456789012"},
			Ownership: protocol.Ownership{Team: "Payments", Service: "Auth", Purpose: "test", Criticality: "high"},
			Policy:    protocol.LifecyclePolicy{RenewalPeriod: "P90D"},
			State:     protocol.StateActive, Health: protocol.HealthHealthy,
			ExpiresAt: testNow().Add(90 * 24 * time.Hour),
			Metadata:  protocol.Metadata{"vault_version": "v9", "common_vault_url": "http://mutandae-vault.mutandae.svc", "common_vault_secret": "identities/both-vaults", "common_vault_version": "7"},
		},
		{
			ID: "cluster-only", Name: "cluster-only", Environment: "production",
			Provider:  protocol.ProviderBinding{Provider: "gcp-iam", ProviderID: "1", ProjectID: "test-project"},
			Ownership: protocol.Ownership{Team: "Commerce", Service: "Stock", Purpose: "test", Criticality: "high"},
			Policy:    protocol.LifecyclePolicy{RenewalPeriod: "P90D"},
			State:     protocol.StateActive, Health: protocol.HealthHealthy,
			ExpiresAt: testNow().Add(90 * 24 * time.Hour),
			Metadata:  protocol.Metadata{"common_vault_version": "2"},
		},
	}}
	handler, err := NewServer(Dependencies{
		Lifecycle:     fake,
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	body := dashboardBody(t, handler, "/")
	// Native line stays as today, plus a second small cluster line.
	if !strings.Contains(body, "Secrets Manager</strong><small>version v9</small>") {
		t.Error("native vault line changed unexpectedly")
	}
	if !strings.Contains(body, "μVault (cluster) · v7") {
		t.Error("identity with both vaults must show the cluster vault line")
	}
	// Cluster-only vault gets the same marked treatment as a native vault.
	if !strings.Contains(body, "μVault (cluster)</strong><small>version 2</small>") {
		t.Error("identity with only a cluster vault must show the cluster vault line instead of the em-dash")
	}
	if strings.Contains(body, "vault-none") {
		t.Error("no row without a vault copy remains, so the em-dash must be gone")
	}
}

// clusterVaultLifecycle makes the fake's vault reference point at the
// in-cluster μVault so the use fragment must name it honestly.
type clusterVaultLifecycle struct {
	fakeLifecycle
}

func (f *clusterVaultLifecycle) Use(ctx context.Context, req protocol.UseRequest, now time.Time) (protocol.UseResponse, error) {
	resp, err := f.fakeLifecycle.Use(ctx, req, now)
	if err != nil {
		return resp, err
	}
	if resp.Vault != nil {
		resp.Vault.URL = "http://mutandae-vault.mutandae.svc.cluster.local:8200"
	}
	return resp, err
}

func TestUseResultNamesClusterVault(t *testing.T) {
	handler, err := NewServer(Dependencies{
		Lifecycle:     &clusterVaultLifecycle{},
		Configuration: provisioningConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	provisionResp, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", strings.NewReader(`{"provider":"aws-iam"}`))
	if err != nil {
		t.Fatalf("api provision: %v", err)
	}
	_ = provisionResp.Body.Close()

	useResp, err := http.Post(server.URL+"/identities/prov-1/use", "text/plain", nil)
	if err != nil {
		t.Fatalf("use: %v", err)
	}
	defer useResp.Body.Close()
	raw := readAll(t, useResp.Body)
	if useResp.StatusCode != http.StatusOK {
		t.Fatalf("use status = %d body %s", useResp.StatusCode, raw)
	}
	if !strings.Contains(raw, "the cluster μVault vault") {
		t.Errorf("use fragment must name the cluster μVault: %s", raw)
	}
	if !strings.Contains(raw, "Retrieved from <code>mutandae-demo-abc1</code>") {
		t.Errorf("use fragment lost the vault secret name: %s", raw)
	}
}

func TestProvisionResultNamesNativeVault(t *testing.T) {
	handler := newProvisioningServer(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	form := strings.NewReader(`{"provider":"aws-iam"}`)
	resp, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", form)
	if err != nil {
		t.Fatalf("api provision: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("api provision status = %d", resp.StatusCode)
	}

	useResp, err := http.Post(server.URL+"/identities/prov-1/use", "text/plain", nil)
	if err != nil {
		t.Fatalf("use: %v", err)
	}
	defer useResp.Body.Close()
	raw := readAll(t, useResp.Body)
	if !strings.Contains(raw, "in Secrets Manager.") {
		t.Errorf("use fragment must name the provider-native vault: %s", raw)
	}
}
