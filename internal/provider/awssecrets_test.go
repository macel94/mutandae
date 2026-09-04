package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

const awsSecretsFixedDate = "2026-08-20T12:00:00Z"

func awsSecretsTestTime() time.Time {
	fixed, err := time.Parse(time.RFC3339, awsSecretsFixedDate)
	if err != nil {
		panic(err)
	}
	return fixed
}

func newAWSSecretsTestAdapter(t *testing.T, handler http.Handler, sessionToken string) (*AWSAdapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:              fakeAWSAccount,
		Region:                 "us-west-2",
		AccessKeyID:            fakeAccessKeyID,
		SecretKey:              fakeSigningSecret,
		SessionToken:           sessionToken,
		SecretsManager:         true,
		SecretsManagerEndpoint: server.URL,
		HTTPClient:             server.Client(),
		Now:                    awsSecretsTestTime,
	})
	if err != nil {
		server.Close()
		t.Fatalf("NewAWSAdapter() for Secrets Manager: %v", err)
	}
	return adapter, server
}

func awsSecretsTestIdentity() protocol.MachineIdentity {
	return protocol.MachineIdentity{
		Name: "mutandae-demo-orders",
		Provider: protocol.ProviderBinding{
			Provider:   awsKind,
			ProviderID: "mutandae-demo-orders",
			AccountID:  fakeAWSAccount,
			Region:     "us-west-2",
		},
		ExpiresAt: awsSecretsTestTime().Add(24 * time.Hour),
	}
}

func assertAWSSecretsRequest(t *testing.T, r *http.Request, operation string, sessionToken bool) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("%s request method = %q, want POST", operation, r.Method)
	}
	wantTarget := "secretsmanager." + operation
	if got := r.Header.Get("X-Amz-Target"); got != wantTarget {
		t.Errorf("%s X-Amz-Target = %q, want %q; headers=%v", operation, got, wantTarget, r.Header)
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-amz-json-1.1" {
		t.Errorf("%s Content-Type = %q, want application/x-amz-json-1.1; headers=%v", operation, got, r.Header)
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 Credential=") {
		t.Errorf("%s Authorization = %q, want AWS4-HMAC-SHA256 Credential= prefix; headers=%v", operation, authorization, r.Header)
	}
	wantSignedHeaders := "content-type;host;x-amz-date;x-amz-target"
	if sessionToken {
		wantSignedHeaders = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
	}
	if !strings.Contains(authorization, "SignedHeaders="+wantSignedHeaders+",") {
		t.Errorf("%s Authorization signed headers = %q, want %q; full authorization=%q", operation, authorization, wantSignedHeaders, authorization)
	}
	wantDate := awsSecretsTestTime().UTC().Format("20060102T150405Z")
	if got := r.Header.Get("X-Amz-Date"); got != wantDate {
		t.Errorf("%s X-Amz-Date = %q, want fixed %q; headers=%v", operation, got, wantDate, r.Header)
	}
	if sessionToken && r.Header.Get("X-Amz-Security-Token") == "" {
		t.Errorf("%s missing X-Amz-Security-Token; headers=%v", operation, r.Header)
	}
}

func TestAWSStoreSecret(t *testing.T) {
	identity := awsSecretsTestIdentity()
	secret := "store-secret-value"
	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAWSSecretsRequest(t, r, "PutSecretValue", false)
		var payload struct {
			SecretID     string `json:"SecretId"`
			SecretString string `json:"SecretString"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("PutSecretValue request JSON decode failed: %v", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
		if payload.SecretID != wantName {
			t.Errorf("PutSecretValue SecretId = %q, want %q; payload=%+v", payload.SecretID, wantName, payload)
		}
		if payload.SecretString != secret {
			t.Errorf("PutSecretValue SecretString = %q, want %q; payload fields=%+v", payload.SecretString, secret, payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"VersionId": "v1",
			"Name":      wantName,
		})
	})
	adapter, server := newAWSSecretsTestAdapter(t, serverHandler, "")
	defer server.Close()
	defer adapter.Close()

	ref, err := adapter.StoreSecret(context.Background(), identity, "access-key-1", secret)
	if err != nil {
		t.Fatalf("StoreSecret() error = %v", err)
	}
	wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
	if ref.URL != server.URL || ref.SecretName != wantName || ref.Version != "v1" || !ref.ExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatalf("StoreSecret() reference = %+v, want URL=%q name=%q version=v1 expires_at=%v", ref, server.URL, wantName, identity.ExpiresAt)
	}
	if strings.Contains(fmt.Sprintf("%+v", ref), secret) {
		t.Fatalf("StoreSecret() reference contains secret value: %+v", ref)
	}
}

func TestAWSStoreSecretCreatesMissingSecretAndRetries(t *testing.T) {
	identity := awsSecretsTestIdentity()
	secret := "fallback-secret-value"
	var operations []string
	putCalls := 0
	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")
		operations = append(operations, operation)
		assertAWSSecretsRequest(t, r, operation, true)
		switch operation {
		case "PutSecretValue":
			putCalls++
			var payload struct {
				SecretID     string `json:"SecretId"`
				SecretString string `json:"SecretString"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("PutSecretValue #%d request JSON decode failed: %v", putCalls, err)
				return
			}
			if payload.SecretString != secret {
				t.Errorf("PutSecretValue #%d SecretString = %q, want %q; payload fields=%+v", putCalls, payload.SecretString, secret, payload)
			}
			if putCalls == 1 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"__type":"ResourceNotFoundException"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"VersionId": "v2", "Name": payload.SecretID})
		case "CreateSecret":
			var payload struct {
				Name         string                 `json:"Name"`
				SecretString string                 `json:"SecretString"`
				Description  string                 `json:"Description"`
				Tags         []awsSecretsManagerTag `json:"Tags"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("CreateSecret request JSON decode failed: %v", err)
				return
			}
			if payload.SecretString != secret {
				t.Errorf("CreateSecret SecretString = %q, want %q; payload fields=%+v", payload.SecretString, secret, payload)
			}
			if payload.Description != "Mutandae demo credential" {
				t.Errorf("CreateSecret Description = %q, want Mutandae demo credential; payload=%+v", payload.Description, payload)
			}
			gotTags := make(map[string]string, len(payload.Tags))
			for _, tag := range payload.Tags {
				gotTags[tag.Key] = tag.Value
			}
			wantTags := map[string]string{
				"MutandaeIdentity": identity.Name,
				"MutandaeKeyId":    "access-key-2",
				"MutandaeProvider": awsKind,
			}
			if len(gotTags) != len(wantTags) {
				t.Errorf("CreateSecret Tags = %v, want %v; payload=%+v", gotTags, wantTags, payload)
			}
			for key, want := range wantTags {
				if got := gotTags[key]; got != want {
					t.Errorf("CreateSecret tag %q = %q, want %q; all tags=%v", key, got, want, gotTags)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"VersionId": "created-version", "Name": payload.Name})
		default:
			t.Errorf("unexpected Secrets Manager operation %q; headers=%v", operation, r.Header)
			http.Error(w, "unexpected operation", http.StatusBadRequest)
		}
	})
	adapter, server := newAWSSecretsTestAdapter(t, serverHandler, "session-token")
	defer server.Close()
	defer adapter.Close()

	ref, err := adapter.StoreSecret(context.Background(), identity, "access-key-2", secret)
	if err != nil {
		t.Fatalf("StoreSecret() fallback error = %v", err)
	}
	if putCalls != 2 {
		t.Fatalf("PutSecretValue call count = %d, want 2; operations=%v", putCalls, operations)
	}
	wantOperations := []string{"PutSecretValue", "CreateSecret", "PutSecretValue"}
	if fmt.Sprint(operations) != fmt.Sprint(wantOperations) {
		t.Fatalf("Secrets Manager operation sequence = %v, want %v", operations, wantOperations)
	}
	if ref.Version != "v2" {
		t.Fatalf("fallback reference version = %q, want v2; ref=%+v", ref.Version, ref)
	}
}

func TestAWSReadSecretRoundTrip(t *testing.T) {
	identity := awsSecretsTestIdentity()
	calls := 0
	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assertAWSSecretsRequest(t, r, "GetSecretValue", false)
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("GetSecretValue request JSON decode failed: %v", err)
			return
		}
		wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
		if payload["SecretId"] != wantName {
			t.Errorf("GetSecretValue SecretId = %q, want %q; payload=%v", payload["SecretId"], wantName, payload)
		}
		if calls == 1 {
			if payload["VersionId"] != "v1" || payload["VersionStage"] != "" {
				t.Errorf("pinned GetSecretValue selector = %v, want VersionId=v1 and no VersionStage; payload=%v", payload, payload)
			}
		} else if payload["VersionStage"] != "AWSCURRENT" || payload["VersionId"] != "" {
			t.Errorf("current GetSecretValue selector = %v, want VersionStage=AWSCURRENT and no VersionId; payload=%v", payload, payload)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ARN":          "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
			"Name":         wantName,
			"VersionId":    "v1",
			"SecretString": "the-value",
		})
	})
	adapter, server := newAWSSecretsTestAdapter(t, serverHandler, "")
	defer server.Close()
	defer adapter.Close()

	value, ref, err := adapter.ReadSecret(context.Background(), identity, "access-key-1", "v1")
	if err != nil {
		t.Fatalf("ReadSecret(pinned) error = %v", err)
	}
	if value != "the-value" {
		t.Fatalf("ReadSecret(pinned) value = %q, want the-value", value)
	}
	wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
	if ref.URL != server.URL || ref.SecretName != wantName || ref.Version != "v1" || !ref.ExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatalf("ReadSecret(pinned) reference = %+v, want URL=%q name=%q version=v1 expires_at=%v", ref, server.URL, wantName, identity.ExpiresAt)
	}

	value, currentRef, err := adapter.ReadSecret(context.Background(), identity, "access-key-1", "current")
	if err != nil {
		t.Fatalf("ReadSecret(current) error = %v", err)
	}
	if value != "the-value" || currentRef.Version != "v1" || calls != 2 {
		t.Fatalf("ReadSecret(current) = %q, %+v after %d calls; want value the-value, version v1, two calls", value, currentRef, calls)
	}
}

func TestAWSRevokeSecretIsIdempotent(t *testing.T) {
	identity := awsSecretsTestIdentity()
	calls := 0
	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assertAWSSecretsRequest(t, r, "DeleteSecret", false)
		var payload struct {
			SecretID             string `json:"SecretId"`
			RecoveryWindowInDays int    `json:"RecoveryWindowInDays"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("DeleteSecret request JSON decode failed: %v", err)
			return
		}
		wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
		if payload.SecretID != wantName || payload.RecoveryWindowInDays != 7 {
			t.Errorf("DeleteSecret payload = %+v, want SecretId=%q and RecoveryWindowInDays=7", payload, wantName)
		}
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]string{"Name": wantName})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"__type":"ResourceNotFoundException"}`)
	})
	adapter, server := newAWSSecretsTestAdapter(t, serverHandler, "")
	defer server.Close()
	defer adapter.Close()

	ref, err := adapter.RevokeSecret(context.Background(), identity, "access-key-1")
	if err != nil {
		t.Fatalf("RevokeSecret() error = %v", err)
	}
	wantName := "mutandae-demo/" + identity.Name + "/access-key-1"
	if ref.URL != server.URL || ref.SecretName != wantName || !ref.ExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatalf("RevokeSecret() reference = %+v, want URL=%q name=%q expires_at=%v", ref, server.URL, wantName, identity.ExpiresAt)
	}
	second, err := adapter.RevokeSecret(context.Background(), identity, "access-key-1")
	if err != nil {
		t.Fatalf("second RevokeSecret() idempotency error = %v", err)
	}
	if calls != 2 || second.SecretName != wantName {
		t.Fatalf("second RevokeSecret() = %+v after %d calls, want same name and two calls", second, calls)
	}
}

func TestAWSSecretsCapabilityDisabled(t *testing.T) {
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:   fakeAWSAccount,
		Region:      "us-west-2",
		AccessKeyID: fakeAccessKeyID,
		SecretKey:   fakeSigningSecret,
		Now:         awsSecretsTestTime,
	})
	if err != nil {
		t.Fatalf("NewAWSAdapter() error = %v", err)
	}
	defer adapter.Close()
	identity := awsSecretsTestIdentity()

	if _, err := adapter.StoreSecret(context.Background(), identity, "key", "secret"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("StoreSecret() disabled error = %v, want ErrVaultUnsupported", err)
	}
	if _, _, err := adapter.ReadSecret(context.Background(), identity, "key", "current"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("ReadSecret() disabled error = %v, want ErrVaultUnsupported", err)
	}
	if _, err := adapter.RevokeSecret(context.Background(), identity, "key"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("RevokeSecret() disabled error = %v, want ErrVaultUnsupported", err)
	}
}

func TestAWSSecretsRejectNonDemoIdentity(t *testing.T) {
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:              fakeAWSAccount,
		Region:                 "us-west-2",
		AccessKeyID:            fakeAccessKeyID,
		SecretKey:              fakeSigningSecret,
		SecretsManager:         true,
		SecretsManagerEndpoint: "://invalid-endpoint",
		Now:                    awsSecretsTestTime,
	})
	if err != nil {
		t.Fatalf("NewAWSAdapter() error = %v", err)
	}
	defer adapter.Close()
	identity := awsSecretsTestIdentity()
	identity.Name = "production-user"

	for _, test := range []struct {
		name string
		call func() error
	}{
		{
			name: "StoreSecret",
			call: func() error {
				_, err := adapter.StoreSecret(context.Background(), identity, "key", "secret")
				return err
			},
		},
		{
			name: "ReadSecret",
			call: func() error {
				_, _, err := adapter.ReadSecret(context.Background(), identity, "key", "current")
				return err
			},
		},
		{
			name: "RevokeSecret",
			call: func() error {
				_, err := adapter.RevokeSecret(context.Background(), identity, "key")
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil {
				t.Fatalf("%s accepted non-demo identity", test.name)
			}
			if !strings.Contains(err.Error(), "mutandae-demo-*") {
				t.Fatalf("%s error = %v, want mutandae-demo-* namespace guard", test.name, err)
			}
		})
	}
}

func TestAWSSecretsRejectsInvalidName(t *testing.T) {
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:      fakeAWSAccount,
		Region:         "us-west-2",
		AccessKeyID:    fakeAccessKeyID,
		SecretKey:      fakeSigningSecret,
		SecretsManager: true,
		Now:            awsSecretsTestTime,
	})
	if err != nil {
		t.Fatalf("NewAWSAdapter() error = %v", err)
	}
	defer adapter.Close()

	identity := awsSecretsTestIdentity()
	identity.Name = "mutandae-demo-" + strings.Repeat("a", 510)
	if _, err := adapter.StoreSecret(context.Background(), identity, "key", "secret"); err == nil {
		t.Fatal("StoreSecret() accepted a derived name longer than 512 characters")
	}
	identity.Name = "mutandae-demo-valid?name"
	if _, _, err := adapter.ReadSecret(context.Background(), identity, "key", "current"); err == nil {
		t.Fatal("ReadSecret() accepted a derived name containing an invalid character")
	}
}

// TestAWSSecretsDenialMapsToUnsupported proves the live-demo degradation path:
// when Secrets Manager deterministically denies the governor (the demo grants
// no secretsmanager permissions), every vault operation reports the canonical
// ErrVaultUnsupported so delivery skips silently and reads fall back to the
// cluster μVault copy instead of failing.
func TestAWSSecretsDenialMapsToUnsupported(t *testing.T) {
	secret := "write-only-secret-value"
	var calls int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"com.amazonaws.secretsmanager#AccessDeniedException","code":"AccessDeniedException","message":"User is not authorized to perform: secretsmanager:GetSecretValue"}`))
	})
	adapter, server := newAWSSecretsTestAdapter(t, handler, "")
	defer server.Close()
	identity := awsSecretsTestIdentity()

	if _, err := adapter.StoreSecret(context.Background(), identity, "key-1", secret); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("StoreSecret() denied error = %v, want ErrVaultUnsupported", err)
	}
	if _, _, err := adapter.ReadSecret(context.Background(), identity, "key-1", "current"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("ReadSecret() denied error = %v, want ErrVaultUnsupported", err)
	}
	if _, err := adapter.RevokeSecret(context.Background(), identity, "key-1"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("RevokeSecret() denied error = %v, want ErrVaultUnsupported", err)
	}
	if strings.Contains(fmt.Sprint(calls), secret) || calls == 0 {
		t.Errorf("denial handler call count = %d, want >0", calls)
	}
}
