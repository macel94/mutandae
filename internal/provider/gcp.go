package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// gcpKind ("gcp-iam") is declared in gcpsimulator.go and shared by the real
// adapter so both implementations produce identical ProviderBindings.

const (
	gcpIAMScope = "https://www.googleapis.com/auth/cloud-platform"
	gcpTokenURI = "https://oauth2.googleapis.com/token"
	gcpIAMBase  = "https://iam.googleapis.com/v1"
	// gcpSecretBase is the official Secret Manager API base used for vault
	// delivery; tests override it through GCPAdapterConfig.SecretManagerBaseURL.
	gcpSecretBase = "https://secretmanager.googleapis.com/v1"
	gcpMaxKeys    = 10 // IAM hard ceiling for user-managed service account keys
)

// GCPAdapterConfig carries the connection material for a real GCP IAM adapter.
// KeyJSON is the service account JSON key file (including private_key), which
// is write-only: it signs the JWT assertion and is never returned or placed
// into any protocol object.
type GCPAdapterConfig struct {
	// ProjectID is the Google Cloud project that owns the governed service
	// accounts.
	ProjectID string
	// Region is surfaced in ProviderBinding.Region for UI scope display.
	Region string
	// KeyJSON holds the service account JSON key file contents (secret).
	KeyJSON string
	// TokenURI overrides the OAuth2 token endpoint (used by tests; default is
	// the official https://oauth2.googleapis.com/token).
	TokenURI string
	// IAMBaseURL overrides the IAM API base (used by tests; default is the
	// official https://iam.googleapis.com/v1).
	IAMBaseURL string
	// HTTPClient overrides the transport used for IAM calls.
	HTTPClient *http.Client
	// Now pins the provider clock for deterministic tests.
	Now func() time.Time
	// Scope restricts which service-account email/name values this adapter may
	// govern. Patterns use path.Match's fnmatch-style syntax, not regular
	// expressions. Real adapters require at least one Allow pattern.
	Scope Scope
	// DemoOnly is retained as a deprecated internal compatibility bridge. New
	// callers must use Scope; true maps to the safe mutandae-demo-* scope.
	DemoOnly bool
	// SecretManager enables the vault delivery capability: provisioned and
	// renewed demo credentials are stored as versions of a Secret Manager
	// secret in the same project. The governor service account needs the
	// least-privilege secretmanager roles documented in docs/live-demo.md.
	SecretManager bool
	// SecretManagerBaseURL overrides the Secret Manager API base (used by
	// tests; default is the official https://secretmanager.googleapis.com/v1).
	SecretManagerBaseURL string
}

type gcpServiceAccount struct {
	Name        string `json:"name"` // projects/{project}/serviceAccounts/{email}
	ProjectID   string `json:"projectId"`
	UniqueID    string `json:"uniqueId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`
}

type gcpServiceAccountKey struct {
	Name            string `json:"name"` // projects/{project}/serviceAccounts/{email}/keys/{id}
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyOrigin       string `json:"keyOrigin"`
	KeyType         string `json:"keyType"`
	ValidAfterTime  string `json:"validAfterTime"`
	ValidBeforeTime string `json:"validBeforeTime"`
	Disabled        bool   `json:"disabled"`
	PrivateKeyData  string `json:"privateKeyData"` // base64 PKCS#8 private key, returned only at create
}

// GCPAdapter is a real Google Cloud IAM adapter behind the CloudAdapter
// boundary. It authenticates with a service-account JWT (RS256) assertion and
// speaks the iam.googleapis.com REST API using only the Go standard library.
//
// Trust boundary: IAM returns the private key only from keys.create and never
// again. The adapter keeps the freshly created key in process memory purely for
// immediate one-time handoff (ConsumeOneTimeSecret) and clears it when it is
// consumed, on the next rotation, or on Close.
type GCPAdapter struct {
	projectID     string
	region        string
	clientEmail   string
	privateKey    *rsa.PrivateKey
	tokenURI      string
	iamBaseURL    string
	secretBaseURL string
	secretManager bool
	httpClient    *http.Client
	now           func() time.Time
	scope         Scope
	// scopeConfigured distinguishes explicit provider scope configuration from
	// legacy direct-constructor fixtures. Production composition always passes
	// an explicit scope; the distinction keeps old vault fixtures compatible
	// without weakening explicitly scoped adapters.
	scopeConfigured bool
	// demoOnly remains for old in-package callers; Scope is authoritative for
	// all new construction and wiring.
	demoOnly bool

	mu             sync.Mutex
	accessToken    string
	tokenExpiresAt time.Time
	oneTimeSecret  string
	oneTimeKeyID   string
	oneTimeCreated time.Time
}

// NewGCPAdapter validates the service-account key material and returns a real
// IAM adapter. It does not contact Google; the first discovery verifies access.
func NewGCPAdapter(cfg GCPAdapterConfig) (*GCPAdapter, error) {
	projectID := strings.TrimSpace(cfg.ProjectID)
	if projectID == "" {
		return nil, errors.New("gcp: project_id is required")
	}
	if strings.TrimSpace(cfg.KeyJSON) == "" {
		return nil, errors.New("gcp: service account key json is required")
	}
	scope, err := validateRealScope(cfg.Scope, cfg.DemoOnly)
	if err != nil {
		return nil, fmt.Errorf("gcp: %w", err)
	}
	var keyFile struct {
		Type           string `json:"type"`
		ProjectID      string `json:"project_id"`
		PrivateKeyID   string `json:"private_key_id"`
		PrivateKey     string `json:"private_key"`
		ClientEmail    string `json:"client_email"`
		ClientID       string `json:"client_id"`
		TokenURI       string `json:"token_uri"`
		UniverseDomain string `json:"universe_domain"`
	}
	if err := json.Unmarshal([]byte(cfg.KeyJSON), &keyFile); err != nil {
		return nil, fmt.Errorf("gcp: decode service account key json: %w", err)
	}
	if keyFile.PrivateKey == "" || keyFile.ClientEmail == "" {
		return nil, errors.New("gcp: service account key json must contain private_key and client_email")
	}
	privateKey, err := parseRSAPrivateKey([]byte(keyFile.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("gcp: parse private key: %w", err)
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-central1"
	}
	tokenURI := strings.TrimSpace(cfg.TokenURI)
	if tokenURI == "" && keyFile.TokenURI != "" {
		tokenURI = keyFile.TokenURI
	}
	if tokenURI == "" {
		tokenURI = gcpTokenURI
	}
	iamBaseURL := strings.TrimSpace(cfg.IAMBaseURL)
	if iamBaseURL == "" {
		iamBaseURL = gcpIAMBase
	}
	secretBaseURL := strings.TrimSpace(cfg.SecretManagerBaseURL)
	if secretBaseURL == "" {
		secretBaseURL = gcpSecretBase
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &GCPAdapter{
		projectID:       projectID,
		region:          region,
		clientEmail:     keyFile.ClientEmail,
		privateKey:      privateKey,
		tokenURI:        tokenURI,
		iamBaseURL:      strings.TrimSuffix(iamBaseURL, "/"),
		secretBaseURL:   strings.TrimSuffix(secretBaseURL, "/"),
		secretManager:   cfg.SecretManager,
		httpClient:      httpClient,
		now:             now,
		scope:           scope,
		scopeConfigured: len(cfg.Scope.Allow) > 0 || len(cfg.Scope.Deny) > 0 || cfg.DemoOnly,
		demoOnly:        cfg.DemoOnly,
	}, nil
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("expected a PEM encoded private key")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key encoding")
}

// Kind returns the stable provider identifier.
func (a *GCPAdapter) Kind() string { return gcpKind }

// Scope returns the active non-secret governance scope.
func (a *GCPAdapter) Scope() Scope { return a.scope }

func (a *GCPAdapter) inScope(name string) bool {
	if a.demoOnly && !a.scopeConfigured {
		return DemoScope().Match(name)
	}
	return a.scope.Match(name)
}

// ConsumeOneTimeSecret returns and clears the most recent one-time private key
// (decoded PEM) created by Rotate. Nothing in the protocol ever carries it.
func (a *GCPAdapter) ConsumeOneTimeSecret() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	value := a.oneTimeSecret
	a.oneTimeSecret = ""
	a.oneTimeKeyID = ""
	return value
}

// OneTimeKeyID reports which key the most recent one-time material belongs to.
func (a *GCPAdapter) OneTimeKeyID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.oneTimeKeyID
}

// Close clears secret material held by this adapter.
func (a *GCPAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.privateKey = nil
	a.accessToken = ""
	a.oneTimeSecret = ""
	a.oneTimeKeyID = ""
}

// Discover returns the provider's current view of machine identities: every
// enabled service account that owns at least one user-managed (downloadable)
// key. Governed expiry uses the key's valid-before window when IAM reports one.
func (a *GCPAdapter) Discover(ctx context.Context) ([]protocol.MachineIdentity, error) {
	accounts, err := a.listServiceAccounts(ctx)
	if err != nil {
		return nil, err
	}
	identities := make([]protocol.MachineIdentity, 0, len(accounts))
	for _, account := range accounts {
		if account.Disabled {
			continue
		}
		// Scope filtering happens before key enumeration, so identities outside
		// the allow-list remain invisible.
		if !a.inScope(account.Email) {
			continue
		}
		keys, err := a.listKeys(ctx, account.Email)
		if err != nil {
			return nil, fmt.Errorf("%s: service account %q: %w", gcpKind, account.Email, err)
		}
		if len(keys) == 0 {
			continue // no downloadable credential; not governed by Mutandae
		}
		identities = append(identities, a.toIdentity(account, keys))
	}
	return identities, nil
}

// toIdentity builds a conformant MachineIdentity from a service account and
// its user-managed keys. The newest enabled key is the identity's credential.
func (a *GCPAdapter) toIdentity(account gcpServiceAccount, keys []gcpServiceAccountKey) protocol.MachineIdentity {
	sort.SliceStable(keys, func(i, j int) bool {
		iCreated := gcpKeyCreated(keys[i])
		jCreated := gcpKeyCreated(keys[j])
		if iCreated.Equal(jCreated) {
			return keys[i].Name > keys[j].Name
		}
		if jCreated.IsZero() {
			return false
		}
		if iCreated.IsZero() {
			return true
		}
		return iCreated.After(jCreated)
	})
	key := keys[0]
	keyID := gcpKeyID(key.Name)
	expiresAt := gcpKeyExpiry(key)
	if expiresAt.IsZero() {
		expiresAt = a.now().UTC().Add(90 * 24 * time.Hour)
	}
	health := protocol.HealthHealthy
	if !a.now().UTC().Before(expiresAt) {
		health = protocol.HealthAttention
	}
	return protocol.MachineIdentity{
		Name:        account.Email,
		DisplayName: account.DisplayName,
		Environment: "production",
		Provider: protocol.ProviderBinding{
			Provider:   gcpKind,
			ProviderID: account.UniqueID,
			ProjectID:  a.projectID,
			Region:     a.region,
		},
		Ownership: protocol.Ownership{
			Team:        "GCP IAM",
			Service:     account.Email,
			Purpose:     "Machine workload identity",
			Criticality: "medium",
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    "P90D",
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "service_account_key",
			Location:    "iam://projects/" + a.projectID + "/serviceAccounts/" + account.Email + "/keys/" + keyID,
			Fingerprint: gcpFingerprint(key.Name),
			KeyID:       keyID,
			Delivery:    "secret-manager",
		},
		State:         protocol.StateActive,
		Health:        health,
		ExpiresAt:     expiresAt,
		LastRotatedAt: gcpKeyCreated(key),
	}
}

// gcpFingerprint derives deterministic verification metadata from the provider
// key resource name. IAM exposes no fingerprint; the digest is based on the
// key id so rotation visibly replaces the key without touching secret material.
func gcpFingerprint(keyName string) string {
	sum := sha256.Sum256([]byte(keyName))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func gcpKeyID(keyName string) string {
	if index := strings.LastIndex(keyName, "/"); index >= 0 && index+1 < len(keyName) {
		return keyName[index+1:]
	}
	return keyName
}

func gcpKeyCreated(key gcpServiceAccountKey) time.Time {
	if key.ValidAfterTime == "" {
		return time.Time{}
	}
	if value, err := time.Parse(time.RFC3339, key.ValidAfterTime); err == nil {
		return value
	}
	return time.Time{}
}

func gcpKeyExpiry(key gcpServiceAccountKey) time.Time {
	if key.ValidBeforeTime == "" {
		return time.Time{}
	}
	if value, err := time.Parse(time.RFC3339, key.ValidBeforeTime); err == nil {
		return value
	}
	return time.Time{}
}

// Rotate replaces the service account's user-managed key: the new key is
// created (capturing the one-time private key), then the rotated-out key is
// deleted. IAM's hard ceiling of 10 user-managed keys per service account is
// respected by removing a non-current key first when needed.
func (a *GCPAdapter) Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if name := strings.TrimSpace(identity.Name); name != "" && !a.inScope(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, name, a.scope)
	}
	email, err := a.emailFor(ctx, identity.Provider.ProviderID)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if !a.inScope(email) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, email, a.scope)
	}
	keys, err := a.listKeys(ctx, email)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if len(keys) == 0 {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: service account %q has no user-managed keys to rotate", gcpKind, email)
	}
	currentKeyID := strings.TrimSpace(identity.Credential.KeyID)
	current := findGCPKey(keys, currentKeyID)
	if current == nil {
		current = &keys[len(keys)-1]
	}
	if len(keys) >= gcpMaxKeys {
		remove := oldestNonCurrentGCP(keys, current.Name)
		if err := a.deleteKey(ctx, remove.Name); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}
	created, err := a.createKey(ctx, email)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if current.Name != created.Name {
		if err := a.deleteKey(ctx, current.Name); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(created.PrivateKeyData)
	if err != nil {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: decode created key material: %w", gcpKind, err)
	}
	a.mu.Lock()
	a.oneTimeSecret = string(decoded)
	a.oneTimeKeyID = gcpKeyID(created.Name)
	a.oneTimeCreated = a.now().UTC()
	a.mu.Unlock()

	account := gcpServiceAccount{Name: created.Name[:strings.Index(created.Name, "/keys/")], UniqueID: identity.Provider.ProviderID, Email: email, DisplayName: email}
	return a.toIdentity(account, []gcpServiceAccountKey{created}), nil
}

// Retire decommissions the identity in GCP by deleting every user-managed key
// of the service account, revoking all downloadable credentials. The service
// account itself is left in place (deleting it is the caller's cleanup step);
// with all keys deleted it is no longer rediscovered, matching the simulator
// contract.
func (a *GCPAdapter) PlanRotate(ctx context.Context, id string) ([]protocol.PlannedOperation, error) {
	_ = ctx
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan rotate requires an identity id", gcpKind)
	}
	if !a.inScope(name) {
		return nil, forbiddenScopeError(gcpKind, name, a.scope)
	}
	return []protocol.PlannedOperation{
		planned("gcp.delete_key", name, "If the service account is at the ten-key ceiling, remove the oldest non-current user-managed key first.", true, true),
		planned("gcp.create_service_account_key", name, "Create a replacement user-managed key and retain its one-time private material for delivery.", true, false),
		planned("gcp.verify_service_account_key", name, "Use the provider response as evidence that the replacement key is current.", true, false),
		planned("gcp.delete_key", name, "Delete the rotated-out user-managed key after the replacement is available.", false, true),
	}, nil
}

func (a *GCPAdapter) PlanRetire(ctx context.Context, id string) ([]protocol.PlannedOperation, error) {
	_ = ctx
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan retire requires an identity id", gcpKind)
	}
	if !a.inScope(name) {
		return nil, forbiddenScopeError(gcpKind, name, a.scope)
	}
	return []protocol.PlannedOperation{
		planned("gcp.delete_key", name, "Delete every user-managed key so the service account has no downloadable credential.", false, true),
	}, nil
}

func (a *GCPAdapter) PlanRotateIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	// Real GCP mutations resolve the provider id to an email. A plan is
	// provider-neutral, so use the visible identity name when it is the email.
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = identity.Provider.ProviderID
	}
	return a.PlanRotate(ctx, name)
}

func (a *GCPAdapter) PlanRetireIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = identity.Provider.ProviderID
	}
	return a.PlanRetire(ctx, name)
}

func (a *GCPAdapter) Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if name := strings.TrimSpace(identity.Name); name != "" && !a.inScope(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, name, a.scope)
	}
	email, err := a.emailFor(ctx, identity.Provider.ProviderID)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if !a.inScope(email) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, email, a.scope)
	}
	keys, err := a.listKeys(ctx, email)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	for _, key := range keys {
		if err := a.deleteKey(ctx, key.Name); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}
	view := identity
	view.State = protocol.StateRetired
	view.Health = protocol.HealthAttention
	view.Credential = protocol.CredentialReference{
		Kind:     "service_account_key",
		Location: "iam://projects/" + a.projectID + "/serviceAccounts/" + email,
		Delivery: "secret-manager",
	}
	return view, nil
}

// Create provisions a brand-new, zero-permission service account inside the
// configured Scope and one user-managed key, returning the private key exactly
// once. A freshly created service account has NO IAM roles, so it cannot do
// anything until someone grants it access — which the adapter (and the
// governor's least-privilege role) explicitly cannot do. The account ID is
// capped to stay within GCP's 6-30 character service account ID rule.
func (a *GCPAdapter) Create(ctx context.Context, hint string) (protocol.ProvisionResponse, error) {
	if len(hint) > 7 {
		hint = hint[:7]
	}
	name, err := buildScopedName(a.scope, hint, 8)
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	if !a.inScope(name + "@" + a.projectID + ".iam.gserviceaccount.com") {
		return protocol.ProvisionResponse{}, forbiddenScopeError(gcpKind, name, a.scope)
	}
	account, err := a.createServiceAccount(ctx, name, "Mutandae public demo (zero permissions)")
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	key, err := a.createKeyAfterPropagation(ctx, account.Email)
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return protocol.ProvisionResponse{}, fmt.Errorf("%s: decode created key material: %w", gcpKind, err)
	}

	identity := a.toIdentity(account, []gcpServiceAccountKey{key})
	identity.Environment = "demo"
	identity.Ownership = protocol.Ownership{
		Team:        "Demo",
		Service:     account.Email,
		Purpose:     "Public demo identity with zero permissions",
		Criticality: "low",
	}
	return protocol.ProvisionResponse{
		APIVersion:    protocol.Version,
		Identity:      identity,
		OneTimeSecret: string(decoded),
		KeyID:         gcpKeyID(key.Name),
		Instructions:  "This service account has NO IAM roles and cannot do anything on its own. Store the private key now — it will never be shown again.",
	}, nil
}

func (a *GCPAdapter) createServiceAccount(ctx context.Context, accountID, displayName string) (gcpServiceAccount, error) {
	path := a.iamBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/serviceAccounts"
	body := map[string]any{
		"accountId": accountID,
		"serviceAccount": map[string]string{
			"displayName": displayName,
		},
	}
	var account gcpServiceAccount
	if err := a.iamJSON(ctx, http.MethodPost, path, body, &account); err != nil {
		// A previous demo run may have left the service account behind; reuse
		// it rather than failing the create.
		if strings.Contains(err.Error(), "exists") || strings.Contains(err.Error(), "EXISTS") {
			accounts, listErr := a.listServiceAccounts(ctx)
			if listErr != nil {
				return gcpServiceAccount{}, listErr
			}
			wantEmail := accountID + "@" + a.projectID + ".iam.gserviceaccount.com"
			for _, candidate := range accounts {
				if candidate.Email == wantEmail {
					return candidate, nil
				}
			}
		}
		return gcpServiceAccount{}, err
	}
	if account.Email == "" || account.UniqueID == "" {
		return gcpServiceAccount{}, fmt.Errorf("%s: createServiceAccount returned an incomplete response", gcpKind)
	}
	return account, nil
}

// emailFor resolves a service account unique id (the ProviderBinding) to its
// email, refreshing the mapping from IAM so mutations route correctly. IAM's
// list can lag a just-created service account, so the lookup retries briefly
// before giving up.
func (a *GCPAdapter) emailFor(ctx context.Context, uniqueID string) (string, error) {
	const attempts = 4
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		accounts, err := a.listServiceAccounts(ctx)
		if err != nil {
			return "", err
		}
		for _, account := range accounts {
			if account.UniqueID == uniqueID {
				return account.Email, nil
			}
		}
		lastErr = fmt.Errorf("%s: unknown provider id %q", gcpKind, uniqueID)
		if attempt < attempts-1 {
			select {
			case <-time.After(700 * time.Millisecond):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
	return "", lastErr
}

// --- IAM REST API plumbing ---

func findGCPKey(keys []gcpServiceAccountKey, keyID string) *gcpServiceAccountKey {
	for i := range keys {
		if keyID != "" && gcpKeyID(keys[i].Name) == keyID {
			return &keys[i]
		}
	}
	return nil
}

func oldestNonCurrentGCP(keys []gcpServiceAccountKey, currentName string) *gcpServiceAccountKey {
	oldest := &keys[0]
	for i := range keys {
		if keys[i].Name == currentName {
			continue
		}
		if gcpKeyCreated(keys[i]).Before(gcpKeyCreated(*oldest)) || gcpKeyCreated(*oldest).IsZero() {
			oldest = &keys[i]
		}
	}
	return oldest
}

func (a *GCPAdapter) listServiceAccounts(ctx context.Context) ([]gcpServiceAccount, error) {
	var accounts []gcpServiceAccount
	pageToken := ""
	for {
		path := a.iamBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/serviceAccounts?pageSize=100"
		if pageToken != "" {
			path += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var response struct {
			Accounts      []gcpServiceAccount `json:"accounts"`
			NextPageToken string              `json:"nextPageToken"`
		}
		if err := a.iamJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
			return nil, err
		}
		accounts = append(accounts, response.Accounts...)
		if response.NextPageToken == "" {
			break
		}
		pageToken = response.NextPageToken
		if len(accounts) > 10000 {
			return nil, fmt.Errorf("%s: serviceAccounts list pagination exceeded a sane bound", gcpKind)
		}
	}
	return accounts, nil
}

func (a *GCPAdapter) listKeys(ctx context.Context, email string) ([]gcpServiceAccountKey, error) {
	path := a.iamBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/serviceAccounts/" + url.PathEscape(email) + "/keys?keyTypes=USER_MANAGED"
	var response struct {
		Keys []gcpServiceAccountKey `json:"keys"`
	}
	if err := a.iamJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Keys, nil
}

func (a *GCPAdapter) createKey(ctx context.Context, email string) (gcpServiceAccountKey, error) {
	path := a.iamBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/serviceAccounts/" + url.PathEscape(email) + "/keys"
	body := map[string]string{"keyAlgorithm": "KEY_ALG_RSA_2048"}
	var key gcpServiceAccountKey
	if err := a.iamJSON(ctx, http.MethodPost, path, body, &key); err != nil {
		return gcpServiceAccountKey{}, err
	}
	if gcpKeyID(key.Name) == "" {
		return gcpServiceAccountKey{}, fmt.Errorf("%s: keys.create returned an incomplete response", gcpKind)
	}
	return key, nil
}

// createKeyAfterPropagation wraps createKey with a bounded retry for the one
// deterministic post-create race: IAM's serviceAccounts.create may return
// before the new account is visible to keys.create, which answers 404. The
// failed POST never had side effects, so retrying is safe; anything else
// surfaces immediately.
func (a *GCPAdapter) createKeyAfterPropagation(ctx context.Context, email string) (gcpServiceAccountKey, error) {
	const attempts = 5
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(900 * time.Millisecond):
			case <-ctx.Done():
				return gcpServiceAccountKey{}, ctx.Err()
			}
		}
		key, err := a.createKey(ctx, email)
		if err == nil {
			return key, nil
		}
		lastErr = err
		text := err.Error()
		if !strings.Contains(text, "NOT_FOUND") && !strings.Contains(text, "does not exist") {
			return gcpServiceAccountKey{}, err
		}
	}
	return gcpServiceAccountKey{}, lastErr
}

func (a *GCPAdapter) deleteKey(ctx context.Context, keyName string) error {
	path := a.iamBaseURL + "/" + strings.TrimPrefix(keyName, "/")
	return a.iamJSON(ctx, http.MethodDelete, path, nil, nil)
}

// iamJSON performs one authenticated IAM REST call. Tokens are obtained with a
// service-account JWT assertion and cached in memory until near expiry.
func (a *GCPAdapter) iamJSON(ctx context.Context, method, path string, body any, output any) error {
	token, err := a.token(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Only idempotent read/delete requests are retried; a mid-flight transport
	// failure on a POST can mean the server acted, and a blind retry could
	// duplicate a mutation. GETs and DELETEs are safe to repeat.
	attempts := 1
	if method == http.MethodGet || method == http.MethodDelete {
		attempts = 3
	}
	var response *http.Response
	for attempt := 0; attempt < attempts; attempt++ {
		response, err = a.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < attempts-1 && transientTransportError(err) {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		return a.redact(fmt.Sprintf("%s: request failed: %v", method, err))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return a.redact(fmt.Sprintf("%s: read response: %v", method, err))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return a.gcpError(method, path, data, response.StatusCode)
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return a.redact(fmt.Sprintf("%s: decode response: %v", method, err))
	}
	return nil
}

func (a *GCPAdapter) gcpError(method, path string, data []byte, status int) error {
	var errorResponse struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &errorResponse); err == nil && errorResponse.Error.Message != "" {
		return fmt.Errorf("%s %s: Google IAM returned %s (%d): %s", method, path, errorResponse.Error.Status, errorResponse.Error.Code, a.redactString(errorResponse.Error.Message))
	}
	decoded := strings.TrimSpace(string(data))
	if decoded == "" {
		decoded = "(empty response)"
	}
	return a.redact(fmt.Sprintf("%s %s: Google IAM returned HTTP %d: %s", method, path, status, decoded))
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (a *GCPAdapter) token(ctx context.Context) (string, error) {
	now := a.now().UTC()
	a.mu.Lock()
	if a.accessToken != "" && a.tokenExpiresAt.After(now.Add(60*time.Second)) {
		token := a.accessToken
		a.mu.Unlock()
		return token, nil
	}
	a.mu.Unlock()

	assertion, err := a.jwtAssertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Token minting is side-effect free; bounded retry on transient network
	// failures keeps discovery/rotation resilient on unstable paths.
	var response *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		response, err = a.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < 2 && transientTransportError(err) {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				return "", ctx.Err()
			}
			continue
		}
		return "", a.redact(fmt.Sprintf("Google token endpoint request failed: %v", err))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", a.redact(fmt.Sprintf("Google token endpoint read failed: %v", err))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", a.gcpError("POST", a.tokenURI, data, response.StatusCode)
	}
	var payload gcpTokenResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", a.redact(fmt.Sprintf("decode token endpoint response: %v", err))
	}
	if payload.AccessToken == "" {
		decoded := strings.TrimSpace(string(data))
		if len(decoded) > 512 {
			decoded = decoded[:512]
		}
		return "", a.redact(fmt.Sprintf("Google token endpoint returned no access token: %s", decoded))
	}
	a.mu.Lock()
	if a.privateKey == nil {
		a.mu.Unlock()
		return "", errors.New("gcp: adapter is closed")
	}
	a.accessToken = payload.AccessToken
	a.tokenExpiresAt = now.Add(time.Duration(payload.ExpiresIn) * time.Second)
	token := payload.AccessToken
	a.mu.Unlock()
	return token, nil
}

// jwtAssertion builds the RS256 signed JWT bearer assertion for the exchange.
func (a *GCPAdapter) jwtAssertion(now time.Time) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsPayload, err := json.Marshal(map[string]any{
		"iss":   a.clientEmail,
		"scope": gcpIAMScope,
		"aud":   a.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(3600 * time.Second).Unix(),
	})
	if err != nil {
		return "", err
	}
	claims := base64.RawURLEncoding.EncodeToString(claimsPayload)
	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))
	a.mu.Lock()
	privateKey := a.privateKey
	a.mu.Unlock()
	if privateKey == nil {
		return "", errors.New("gcp: adapter is closed")
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// transientTransportError reports network-layer failures that are safe and
// useful to retry for idempotent requests: connection resets, refusals, and
// timeouts. Errors are returned as plain (redacted) errors, so detection uses
// stable message markers rather than the net.Error interface.
func transientTransportError(err error) bool {
	text := err.Error()
	for _, marker := range []string{
		"connection reset by peer",
		"connection refused",
		"use of closed network connection",
		"broken pipe",
		"i/o timeout",
		"network is unreachable",
		"no route to host",
		"TLS handshake timeout",
		"unexpected EOF",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func (a *GCPAdapter) redact(value string) error {
	return errors.New(a.redactString(value))
}
func (a *GCPAdapter) redactString(value string) string {
	a.mu.Lock()
	secrets := []string{a.oneTimeSecret}
	a.mu.Unlock()
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}
