package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testGCPKeyJSON returns a GCP service-account key file with a real RSA key so
// the adapter can perform its JWT assertion against the fake token endpoint.
func testGCPKeyJSON() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	payload := map[string]string{
		"type":           "service_account",
		"project_id":     "demo",
		"private_key_id": "k1",
		"private_key":    string(pemBlock),
		"client_email":   "gov@demo.iam.gserviceaccount.com",
		"client_id":      "1",
	}
	raw, _ := json.Marshal(payload)
	return string(raw)
}

func TestBuildDemoName(t *testing.T) {
	first, err := buildDemoName("web-app", 8)
	if err != nil {
		t.Fatalf("buildDemoName: %v", err)
	}
	if !isDemoName(first) {
		t.Fatalf("name %q lacks the demo prefix", first)
	}
	if len(first) <= len(demoPrefix) {
		t.Fatalf("name %q too short", first)
	}
	// AWS IAM user names cap at 64; keep well under.
	if len(first) > 40 {
		t.Fatalf("AWS name %q too long (%d)", first, len(first))
	}
	// GCP service account IDs cap at 30; the adapter truncates the hint to 7.
	gcp, _ := buildDemoName("abcdefg", 8)
	if len(gcp) > 30 {
		t.Fatalf("GCP account id %q too long (%d)", gcp, len(gcp))
	}
	// Uniqueness across calls even with the same hint.
	second, _ := buildDemoName("web-app", 8)
	if first == second {
		t.Fatalf("expected distinct names, got %q twice", first)
	}
	// Invalid characters are rejected so a caller cannot break out of the
	// namespace or encode shell/URL metacharacters.
	if _, err := buildDemoName("../../etc", 8); err == nil {
		t.Fatal("expected invalid hint to be rejected")
	}
	if _, err := buildDemoName("has space", 8); err == nil {
		t.Fatal("expected space in hint to be rejected")
	}
}

// --- AWS create safety ---

// awsCreateFake records IAM actions and answers the create path.
type awsCreateFake struct {
	mu      sync.Mutex
	actions []string
	userID  int
}

func (f *awsCreateFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.FormValue("Action")
	f.mu.Lock()
	f.actions = append(f.actions, action)
	f.userID++
	id := f.userID
	userName := r.FormValue("UserName")
	f.mu.Unlock()

	switch action {
	case "CreateUser":
		fmt.Fprintf(w, `<CreateUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><CreateUserResult><User><Path>/</Path><UserName>%s</UserName><UserId>AIDADEMO%d</UserId><Arn>arn:aws:iam::123456789012:user/%s</Arn><CreateDate>2026-09-02T00:00:00Z</CreateDate></User></CreateUserResult><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></CreateUserResponse>`, userName, id, userName)
	case "CreateAccessKey":
		fmt.Fprintf(w, `<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><CreateAccessKeyResult><AccessKey><UserName>%s</UserName><AccessKeyId>AKIDEMO%d</AccessKeyId><SecretAccessKey>SECRETVALUE%d</SecretAccessKey><Status>Active</Status><CreateDate>2026-09-02T00:00:00Z</CreateDate></AccessKey></CreateAccessKeyResult><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></CreateAccessKeyResponse>`, userName, id, id)
	case "TagUser":
		fmt.Fprintf(w, `<TagUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></TagUserResponse>`)
	case "ListUsers", "GetUser", "ListAccessKeys":
		// Not needed for the create assertion, but keep requests honest.
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func newCreateAWSAdapter(t *testing.T) (*AWSAdapter, *awsCreateFake) {
	t.Helper()
	rec := &awsCreateFake{}
	server := httptest.NewServer(http.HandlerFunc(rec.ServeHTTP))
	t.Cleanup(server.Close)
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:   "123456789012",
		Region:      "us-east-1",
		AccessKeyID: "AKIATEST",
		SecretKey:   "secret",
		Endpoint:    server.URL,
		HTTPClient:  server.Client(),
		Now:         func() time.Time { return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewAWSAdapter: %v", err)
	}
	return adapter, rec
}

func TestAWSAdapterCreateNeverGrantsPermissions(t *testing.T) {
	adapter, rec := newCreateAWSAdapter(t)
	ctx := context.Background()

	resp, err := adapter.Create(ctx, "trial")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resp.OneTimeSecret == "" {
		t.Fatal("Create returned no one-time secret")
	}
	if resp.Identity.Name == "" || !isDemoName(resp.Identity.Name) {
		t.Fatalf("created identity name %q is not in the demo namespace", resp.Identity.Name)
	}
	if resp.Identity.Credential.KeyID == "" {
		t.Fatal("created identity lacks a credential key id")
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	// Only safe actions may ever be issued. Any policy/group/login/role action
	// would be a privilege-escalation path an external visitor could abuse.
	for _, action := range rec.actions {
		switch action {
		case "CreateUser", "CreateAccessKey", "TagUser":
		default:
			t.Fatalf("Create issued an unexpected (potentially dangerous) IAM action %q", action)
		}
	}
	if len(rec.actions) < 2 {
		t.Fatalf("expected CreateUser+CreateAccessKey at minimum, got %v", rec.actions)
	}
}

// --- GCP create safety ---

// gcpCreateFake answers the IAM REST create path and records paths/methods.
type gcpCreateFake struct {
	mu    sync.Mutex
	calls []string
}

func (f *gcpCreateFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, "/token") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok","expires_in":3600,"token_type":"Bearer"}`)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/serviceAccounts") && r.Method == http.MethodPost:
		var body struct {
			AccountID string `json:"accountId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		name := body.AccountID
		fmt.Fprintf(w, `{"name":"projects/p/serviceAccounts/%s@demo.iam.gserviceaccount.com","projectId":"p","uniqueId":"111","email":"%s@demo.iam.gserviceaccount.com","displayName":"d","disabled":false}`, name, name)
	case strings.HasSuffix(r.URL.Path, "/keys") && r.Method == http.MethodPost:
		fmt.Fprintf(w, `{"name":"projects/p/serviceAccounts/a@demo.iam.gserviceaccount.com/keys/key-1","keyAlgorithm":"KEY_ALG_RSA_2048","keyType":"USER_MANAGED","privateKeyData":"cHJpdmF0ZS1rZXk=","validAfterTime":"2026-09-02T00:00:00Z"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":{"code":404,"message":"not found"}}`)
	}
}

func TestGCPAdapterCreateProducesZeroRoleServiceAccount(t *testing.T) {
	rec := &gcpCreateFake{}
	server := httptest.NewServer(rec)
	t.Cleanup(server.Close)

	adapter, err := NewGCPAdapter(GCPAdapterConfig{
		ProjectID:  "demo",
		Region:     "us-central1",
		KeyJSON:    testGCPKeyJSON(),
		IAMBaseURL: server.URL,
		TokenURI:   server.URL + "/token",
		HTTPClient: server.Client(),
		Now:        func() time.Time { return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewGCPAdapter: %v", err)
	}
	resp, err := adapter.Create(context.Background(), "web")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resp.OneTimeSecret == "" || resp.OneTimeSecret == "cHJpdmF0ZS1rZXk=" {
		t.Fatalf("one-time secret was not decoded: %q", resp.OneTimeSecret)
	}
	if !isDemoName(resp.Identity.Name) {
		t.Fatalf("created identity %q not in the demo namespace", resp.Identity.Name)
	}
	// The adapter must never issue an IAM policy binding call; it can only
	// create SAs and keys (which grant nothing).
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, call := range rec.calls {
		if strings.Contains(call, "setIamPolicy") || strings.Contains(call, "roles/") {
			t.Fatalf("Create issued a role/iam-policy mutation: %s", call)
		}
	}
}
