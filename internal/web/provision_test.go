package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIProvisionReturnsOneTimeSecretAndDoesNotPersistIt(t *testing.T) {
	fake := &fakeLifecycle{}
	handler, err := NewServer(Dependencies{
		Lifecycle:     fake,
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	body := bytes.NewBufferString(`{"provider":"aws-iam","purpose":"try"}`)
	resp, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", body)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provision status = %d", resp.StatusCode)
	}
	var out protocolResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode provision: %v", err)
	}
	_ = resp.Body.Close()
	if out.OneTimeSecret == "" {
		t.Fatal("provision response carried no one-time secret")
	}
	if out.Identity.State != "active" {
		t.Fatalf("provisioned identity state = %q", out.Identity.State)
	}

	// The one-time secret must never appear in the persisted inventory or any
	// subsequent read.
	got, err := http.Get(server.URL + "/api/v1/identities")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(got.Body)
	_ = got.Body.Close()
	if strings.Contains(raw.String(), out.OneTimeSecret) {
		t.Fatal("one-time secret leaked into the identity inventory")
	}

	// A missing provider is rejected before any provisioning.
	resp2, err := http.Post(server.URL+"/api/v1/demo/identities", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("provision (no provider): %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode == http.StatusCreated {
		t.Fatal("provision without provider should not succeed")
	}
}

type protocolResp struct {
	APIVersion    string      `json:"api_version"`
	Identity      identityRaw `json:"identity"`
	OneTimeSecret string      `json:"one_time_secret"`
	KeyID         string      `json:"key_id"`
}

type identityRaw struct {
	State string `json:"state"`
	Name  string `json:"name"`
}
