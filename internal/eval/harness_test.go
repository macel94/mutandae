//go:build realclouds

package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/config"
	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/internal/web"
	"github.com/mutandae/mutandae/pkg/protocol"
)

// realCloudEnabled is the master switch: the harness never runs unless the
// reviewer sets MUTANDAE_EVAL=1 (in addition to the build tag), so a routine
// `go test -tags=realclouds ./...` in an unconfigured environment skips.
func realCloudEnabled() bool { return os.Getenv("MUTANDAE_EVAL") == "1" }

// evalPrefix is the identity-name/provider-id prefix the harness is allowed to
// rotate or retire. Anything else discovered in the account is treated as
// read-only inventory: it validates conformance but is never mutated.
func evalPrefix() string {
	if prefix := strings.TrimSpace(os.Getenv("MUTANDAE_EVAL_PREFIX")); prefix != "" {
		return prefix
	}
	return "mutandae-eval"
}

// eligibleForMutation reports whether an identity is a dedicated eval target.
// GCP identifies by numeric unique id but its Name (email) carries the prefix;
// AWS identifies by IAM user name; Azure simulator object ids are opaque, so
// the azure simulator is always eligible (it is in-memory only).
func eligibleForMutation(identity protocol.MachineIdentity) bool {
	if identity.Provider.Provider == "azure-entra" {
		return true
	}
	prefix := evalPrefix()
	return strings.HasPrefix(identity.Provider.ProviderID, prefix) || strings.HasPrefix(identity.Name, prefix+"@") || strings.HasPrefix(identity.Name, prefix)
}

// gcpKeyJSON returns the service-account key JSON from the environment,
// preferring GCP_SERVICE_ACCOUNT_KEY_JSON and falling back to the file variant.
func gcpKeyJSON() string {
	if value := os.Getenv("GCP_SERVICE_ACCOUNT_KEY_JSON"); value != "" {
		return value
	}
	if path := os.Getenv("GCP_SERVICE_ACCOUNT_KEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data)
		}
	}
	return ""
}

// secretsUnderTest returns the secret values that must never appear in any
// event, snapshot, receipt, log, or HTML render produced by the harness.
func secretsUnderTest() []string {
	secrets := []string{
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AZURE_CLIENT_SECRET"),
	}
	if keyJSON := gcpKeyJSON(); keyJSON != "" {
		var keyFile struct {
			PrivateKey string `json:"private_key"`
		}
		_ = json.Unmarshal([]byte(keyJSON), &keyFile)
		if keyFile.PrivateKey != "" {
			secrets = append(secrets, keyFile.PrivateKey)
		}
	}
	filtered := secrets[:0]
	for _, secret := range secrets {
		if secret != "" && len(secret) >= 4 {
			filtered = append(filtered, secret)
		}
	}
	return filtered
}

// capturedLog is a Logger that records every line so the harness can prove
// secret material never reaches the log stream.
type capturedLog struct{ lines []string }

func (l *capturedLog) Printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// bootServer builds the same composition graph as cmd/mutandae (real adapters
// when credentials are present, simulators otherwise) and returns an
// httptest server plus the captured log.
func bootServer(t *testing.T) (*httptest.Server, *capturedLog) {
	t.Helper()
	if !realCloudEnabled() {
		t.Skip("MUTANDAE_EVAL=1 is not set")
	}
	now := time.Now
	startedAt := now()

	awsSim := provider.NewAWSSimulator(envOr("AWS_ACCOUNT_ID", "123456789012"), envOr("AWS_REGION", "us-east-1"), startedAt)
	gcpSim := provider.NewGCPSimulator(envOr("GCP_PROJECT_ID", "mutandae-demo"), envOr("GCP_REGION", "us-central1"), startedAt)

	var adapters []provider.CloudAdapter
	adapters = append(adapters, provider.NewSimulator(envOr("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo"), startedAt))

	awsAdapter, err := provider.NewAWSAdapter(provider.AWSAdapterConfig{
		AccountID:    envOr("AWS_ACCOUNT_ID", "123456789012"),
		Region:       envOr("AWS_REGION", "us-east-1"),
		AccessKeyID:  os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		Now:          now,
	})
	switch {
	case err != nil && os.Getenv("AWS_ACCESS_KEY_ID") != "":
		t.Fatalf("wire real AWS adapter: %v", err)
	case os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "":
		adapters = append(adapters, awsAdapter)
	default:
		adapters = append(adapters, awsSim)
	}

	gcpAdapter, err := provider.NewGCPAdapter(provider.GCPAdapterConfig{
		ProjectID: envOr("GCP_PROJECT_ID", "mutandae-demo"),
		Region:    envOr("GCP_REGION", "us-central1"),
		KeyJSON:   gcpKeyJSON(),
		Now:       now,
	})
	switch {
	case err != nil && gcpKeyJSON() != "":
		t.Fatalf("wire real GCP adapter: %v", err)
	case gcpKeyJSON() != "":
		adapters = append(adapters, gcpAdapter)
	default:
		adapters = append(adapters, gcpSim)
	}

	multi, err := provider.NewMultiProvider(adapters...)
	if err != nil {
		t.Fatalf("NewMultiProvider() error = %v", err)
	}
	store, err := lifecycle.NewStore(context.Background(), startedAt, multi)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	integration, err := lifecycle.NewIntegrationManager(&lifecycle.MemoryEventPublisher{}, nil, now, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewIntegrationManager() error = %v", err)
	}

	clog := &capturedLog{}
	handler, err := web.NewServer(web.Dependencies{
		Lifecycle:   store,
		Integration: integration,
		Configuration: config.Public{
			Environment: "ci-eval",
			Persistence: "in-memory",
			Provider:    "multi-cloud evaluation",
			Clock:       now,
		},
		Clock:  now,
		Logger: clog,
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, clog
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// doJSON performs an HTTP call against the harness server and returns status,
// body bytes, and the response headers.
func doJSON(t *testing.T, server *httptest.Server, method, path string, body any) (int, []byte, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s body: %v", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Accept", protocol.MediaType)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	t.Logf("%s %s -> %d", method, path, resp.StatusCode)
	return resp.StatusCode, data, resp.Header
}

// assertNoSecrets scans a byte payload for every secret under test.
func assertNoSecrets(t *testing.T, label string, payload []byte) {
	t.Helper()
	text := string(payload)
	for _, secret := range secretsUnderTest() {
		if secret == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaked secret material: %s contains %q", label, text, secret)
		}
	}
}

func TestRealCloudDiscoveryReturnsV1(t *testing.T) {
	server, _ := bootServer(t)
	status, data, headers := doJSON(t, server, http.MethodGet, "/api/v1/", nil)
	if status != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", status)
	}
	if !strings.HasPrefix(headers.Get("Content-Type"), protocol.MediaType) {
		t.Fatalf("content-type = %q, want %s prefix", headers.Get("Content-Type"), protocol.MediaType)
	}
	var index protocol.DiscoveryIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("decode discovery index: %v", err)
	}
	if index.APIVersion != protocol.Version {
		t.Fatalf("api_version = %q, want %s", index.APIVersion, protocol.Version)
	}
	if index.MediaType != protocol.MediaType {
		t.Fatalf("media_type = %q, want %s", index.MediaType, protocol.MediaType)
	}
	rels := make(map[string]bool)
	envelopes := make(map[string]bool)
	for _, res := range index.Resources {
		rels[res.Rel] = true
		envelopes[res.Envelope] = true
	}
	// The issue checklist asks for list/register/rotate/retire relations; the
	// list relation is advertised as rel "identities" with envelope "list".
	for _, want := range []string{"list", "register", "rotate", "retire"} {
		if !envelopes[want] {
			t.Fatalf("discovery index missing %q relation: %+v", want, index.Resources)
		}
	}
	if !rels["identities"] {
		t.Fatalf("discovery index missing identities relation: %+v", index.Resources)
	}
	assertNoSecrets(t, "discovery index", data)
}

func TestRealCloudListReturnsConformantIdentities(t *testing.T) {
	server, _ := bootServer(t)
	status, data, _ := doJSON(t, server, http.MethodGet, "/api/v1/identities", nil)
	if status != http.StatusOK {
		t.Fatalf("list status = %d, want 200", status)
	}
	var response protocol.ListResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if response.Total != len(response.Identities) || response.Total == 0 {
		t.Fatalf("list total = %d, want >0 and equal to %d identities", response.Total, len(response.Identities))
	}
	providers := map[string]int{}
	for _, identity := range response.Identities {
		if err := protocol.ValidateIdentity(&identity); err != nil {
			t.Errorf("identity %q is non-conformant: %v", identity.Name, err)
			continue
		}
		providers[identity.Provider.Provider]++
		switch identity.Provider.Provider {
		case "aws-iam":
			if identity.Provider.AccountID == "" {
				t.Errorf("aws-iam identity %q missing account_id", identity.Name)
			}
		case "gcp-iam":
			if identity.Provider.ProjectID == "" {
				t.Errorf("gcp-iam identity %q missing project_id", identity.Name)
			}
		}
	}
	if len(providers) < 2 {
		t.Fatalf("expected multiple providers in the real eval inventory, got %v", providers)
	}
	assertNoSecrets(t, "list response", data)
}

// TestRealCloudRotateAndRetire drives the lifecycle on the eval target(s): the
// identities whose provider_id or name carries the eval prefix. Every other
// discovered identity is left untouched (read-only conformance).
func TestRealCloudRotateAndRetire(t *testing.T) {
	server, _ := bootServer(t)

	status, data, _ := doJSON(t, server, http.MethodGet, "/api/v1/identities", nil)
	if status != http.StatusOK {
		t.Fatalf("list status = %d, want 200", status)
	}
	var response protocol.ListResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("decode list: %v", err)
	}

	var targets []protocol.MachineIdentity
	for _, identity := range response.Identities {
		if eligibleForMutation(identity) {
			targets = append(targets, identity)
		}
	}
	if len(targets) == 0 {
		t.Fatal("no eval target identity matched the prefix; nothing to rotate/retire")
	}

	for _, target := range targets {
		target := target
		t.Run(target.Provider.Provider+"/"+target.Name, func(t *testing.T) {
			// Rotate: expect a correlated succeeded run with evidence.
			status, data, _ := doJSON(t, server, http.MethodPost, "/api/v1/identities/"+url.PathEscape(target.ID)+"/rotations", nil)
			if status != http.StatusOK {
				t.Fatalf("rotate status = %d: %s", status, data)
			}
			var rotate protocol.RotateResponse
			if err := json.Unmarshal(data, &rotate); err != nil {
				t.Fatalf("decode rotate: %v", err)
			}
			if rotate.Rotation.Status != protocol.RotationSucceeded {
				t.Fatalf("rotation status = %q, want succeeded", rotate.Rotation.Status)
			}
			if rotate.Rotation.Evidence.KeyID == "" || rotate.Rotation.Evidence.Fingerprint == "" {
				t.Fatalf("rotation evidence incomplete: %+v", rotate.Rotation.Evidence)
			}
			if rotate.Identity.Credential.KeyID == target.Credential.KeyID {
				t.Fatalf("rotation did not replace the provider key id (%s)", rotate.Identity.Credential.KeyID)
			}
			if rotate.Identity.Credential.Fingerprint == target.Credential.Fingerprint {
				t.Fatalf("rotation did not replace the credential fingerprint")
			}
			var started, completed *protocol.LifecycleEvent
			for i := range rotate.Events {
				switch rotate.Events[i].Type {
				case protocol.EventRotationStarted:
					started = &rotate.Events[i]
				case protocol.EventRotationCompleted:
					completed = &rotate.Events[i]
				}
			}
			if started == nil || completed == nil {
				t.Fatalf("missing rotation.started/completed events: %+v", rotate.Events)
			}
			if started.CorrelationID == "" || started.CorrelationID != completed.CorrelationID {
				t.Fatalf("rotation events do not share correlation_id: started=%q completed=%q", started.CorrelationID, completed.CorrelationID)
			}
			if started.CorrelationID != rotate.Rotation.ID {
				t.Fatalf("correlation_id %q does not match rotation run id %q", started.CorrelationID, rotate.Rotation.ID)
			}
			assertNoSecrets(t, "rotate response", data)

			// Retire without confirmation must be rejected with conflict.
			status, data, _ = doJSON(t, server, http.MethodPost, "/api/v1/identities/"+url.PathEscape(target.ID)+"/retire", map[string]any{"confirm": false})
			if status != http.StatusConflict {
				t.Fatalf("unconfirmed retire status = %d, want 409: %s", status, data)
			}
			var failure protocol.ErrorResponse
			if err := json.Unmarshal(data, &failure); err != nil {
				t.Fatalf("decode unconfirmed retire: %v", err)
			}
			if failure.Error.Code != protocol.ErrCodeConflict {
				t.Fatalf("unconfirmed retire error = %+v, want conflict code", failure.Error)
			}
			assertNoSecrets(t, "unconfirmed retire response", data)

			// Retire with confirmation transitions to retired + identity.retired.
			status, data, _ = doJSON(t, server, http.MethodPost, "/api/v1/identities/"+url.PathEscape(target.ID)+"/retire", map[string]any{"confirm": true, "reason": "realcloud eval retire"})
			if status != http.StatusOK {
				t.Fatalf("confirmed retire status = %d: %s", status, data)
			}
			var retired protocol.RetireResponse
			if err := json.Unmarshal(data, &retired); err != nil {
				t.Fatalf("decode retire: %v", err)
			}
			if retired.Identity.State != protocol.StateRetired {
				t.Fatalf("retired identity state = %q, want retired", retired.Identity.State)
			}
			var hadRetired bool
			for _, event := range retired.Events {
				if event.Type == protocol.EventIdentityRetired {
					hadRetired = true
				}
			}
			if !hadRetired {
				t.Fatalf("retire response missing identity.retired event: %+v", retired.Events)
			}
			assertNoSecrets(t, "retire response", data)
		})
	}
}

func TestRealCloudUIRendersProvidersAndControls(t *testing.T) {
	server, _ := bootServer(t)

	// Dashboard.
	status, data, _ := doJSON(t, server, http.MethodGet, "/", nil)
	if status != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", status)
	}
	for _, want := range []string{"AWS IAM", "GCP IAM", "Rotate", "Retire"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("dashboard does not render %q", want)
		}
	}
	assertNoSecrets(t, "dashboard HTML", data)

	// Configuration page.
	status, data, _ = doJSON(t, server, http.MethodGet, "/configuration", nil)
	if status != http.StatusOK {
		t.Fatalf("configuration status = %d, want 200", status)
	}
	assertNoSecrets(t, "configuration HTML", data)

	// Identity list partial.
	status, data, _ = doJSON(t, server, http.MethodGet, "/partials/identities", nil)
	if status != http.StatusOK {
		t.Fatalf("identity partial status = %d, want 200", status)
	}
	if !strings.Contains(string(data), "hx-confirm") || !strings.Contains(string(data), "/rotate") {
		t.Error("identity partial missing rotate/retire controls")
	}
	assertNoSecrets(t, "identity partial HTML", data)
}

func TestRealCloudWebLogsContainNoSecrets(t *testing.T) {
	server, clog := bootServer(t)
	for _, path := range []string{"/api/v1/", "/api/v1/identities", "/", "/configuration", "/partials/identities", "/livez", "/readyz"} {
		status, _, _ := doJSON(t, server, http.MethodGet, path, nil)
		if status != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, status)
		}
	}
	for _, line := range clog.lines {
		for _, secret := range secretsUnderTest() {
			if secret == "" {
				continue
			}
			if strings.Contains(line, secret) {
				t.Fatalf("web log leaked secret material: %s", line)
			}
		}
	}
}
