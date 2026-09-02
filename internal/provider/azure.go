package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

const azureVaultAPI = "2025-07-01"

var (
	guidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	prefixPattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,40}$`)
)

// AzureClient is an ephemeral, real-tenant Microsoft Graph client. It is
// intentionally not serializable and must only be owned by a short-lived
// interactive session. Its credentials are never returned by any method.
type AzureClient struct {
	tenantID     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	now          func() time.Time
	graphBaseURL string
	loginBaseURL string
	closed       bool

	mu               sync.Mutex
	tokens           map[string]accessToken
	callingObjectIDs map[string]struct{}
	callingSPID      string
	createdObjects   map[string]struct{}
	vault            *KeyVaultClient
}

type accessToken struct {
	value     string
	expiresAt time.Time
}

// NewAzureClient validates connection material and creates an ephemeral client.
// It does not contact Azure; Verify must be called before the session is stored.
func NewAzureClient(req protocol.AzureIntegrationRequest, httpClient *http.Client, now func() time.Time) (*AzureClient, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	clientID := strings.TrimSpace(req.ClientID)
	if tenantID == "" || strings.ContainsAny(tenantID, "/?#\r\n") || len(tenantID) > 256 {
		return nil, errors.New("tenant_id must be a valid tenant identifier")
	}
	if !guidPattern.MatchString(clientID) {
		return nil, errors.New("client_id must be a GUID")
	}
	if strings.TrimSpace(req.ClientSecret) == "" || len(req.ClientSecret) > 4096 {
		return nil, errors.New("client_secret is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	client := &AzureClient{
		tenantID:         tenantID,
		clientID:         clientID,
		clientSecret:     req.ClientSecret,
		httpClient:       httpClient,
		now:              now,
		graphBaseURL:     "https://graph.microsoft.com/v1.0",
		loginBaseURL:     "https://login.microsoftonline.com",
		tokens:           make(map[string]accessToken),
		callingObjectIDs: make(map[string]struct{}),
		createdObjects:   make(map[string]struct{}),
	}
	if req.Vault != nil {
		vault, err := NewKeyVaultClient(*req.Vault, client, httpClient, now)
		if err != nil {
			return nil, err
		}
		client.vault = vault
	}
	return client, nil
}

// Verify obtains a Graph token and resolves the supplied client's service
// principal/application object IDs. The result is retained only in memory.
func (c *AzureClient) Verify(ctx context.Context) error {
	if _, err := c.token(ctx, "https://graph.microsoft.com/.default"); err != nil {
		return fmt.Errorf("verify Microsoft Graph access: %w", err)
	}
	var servicePrincipal graphServicePrincipal
	if err := c.graphJSON(ctx, http.MethodGet, "/servicePrincipals(appId='"+c.clientID+"')?$select=id,appId", nil, &servicePrincipal); err != nil {
		return fmt.Errorf("resolve calling service principal: %w", err)
	}
	if servicePrincipal.ID != "" {
		c.mu.Lock()
		c.callingObjectIDs[servicePrincipal.ID] = struct{}{}
		c.callingSPID = servicePrincipal.ID
		c.mu.Unlock()
	}
	var application graphApplication
	if err := c.graphJSON(ctx, http.MethodGet, "/applications(appId='"+c.clientID+"')?$select=id,appId", nil, &application); err == nil && application.ID != "" {
		c.mu.Lock()
		c.callingObjectIDs[application.ID] = struct{}{}
		c.mu.Unlock()
	}
	return nil
}

// Close releases secret material held by this ephemeral client.
func (c *AzureClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.clientSecret = ""
	for key := range c.tokens {
		delete(c.tokens, key)
	}
	c.vault = nil
}

// ListApplications lists safe application metadata. Mutating operations remain
// restricted to applications owned by the calling client.
func (c *AzureClient) ListApplications(ctx context.Context) ([]protocol.AzureApplication, error) {
	var response graphApplicationCollection
	path := "/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials&$top=100"
	if err := c.graphJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	applications := make([]protocol.AzureApplication, 0, len(response.Value))
	for _, application := range response.Value {
		owned, err := c.isOwned(ctx, application.ID)
		if err != nil {
			return nil, err
		}
		converted := application.toProtocol(owned)
		sort.Slice(converted.Credentials, func(i, j int) bool { return converted.Credentials[i].KeyID < converted.Credentials[j].KeyID })
		applications = append(applications, converted)
	}
	sort.Slice(applications, func(i, j int) bool {
		if applications[i].OwnedByCallingClient != applications[j].OwnedByCallingClient {
			return applications[i].OwnedByCallingClient
		}
		return applications[i].DisplayName < applications[j].DisplayName
	})
	return applications, nil
}

// CreateApplication creates an application. Microsoft Entra assigns the
// creating principal as owner for supported application-permission flows; the
// returned object is also tracked in this session as an allowed target.
func (c *AzureClient) CreateApplication(ctx context.Context, req protocol.AzureApplicationCreateRequest) (protocol.AzureApplication, error) {
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || len(name) > 120 {
		return protocol.AzureApplication{}, errors.New("display_name is required and must be at most 120 characters")
	}
	var application graphApplication
	if err := c.graphJSON(ctx, http.MethodPost, "/applications", map[string]string{"displayName": name}, &application); err != nil {
		return protocol.AzureApplication{}, err
	}
	c.waitForApplication(ctx, application.ID)
	c.mu.Lock()
	c.createdObjects[application.ID] = struct{}{}
	c.mu.Unlock()
	// Verification against a real tenant (2026-09-02) proved two Graph facts:
	//  1. client-credentials flow does not auto-assign the creating principal
	//     as owner of the new application;
	//  2. POST /applications/{id}/owners rejects a service principal owner
	//     with Unsupported resource type 'DirectoryObject'.
	// Therefore the adapter records a session creation grant: applications
	// created by this session are owned by this session. isOwned honors that
	// grant; every mutation gate still refuses other tenants' applications.
	return application.toProtocol(true), nil
}

// CreateSecret adds a Graph password credential. When StoreInVault is true,
// plaintext is written to Key Vault before being returned, and no plaintext is
// returned to the caller. A failed vault write triggers best-effort Graph
// removal so an untracked usable credential is not left behind.
func (c *AzureClient) CreateSecret(ctx context.Context, req protocol.AzureSecretCreateRequest, vaultConfig *protocol.VaultConfiguration) (protocol.AzureSecretResult, error) {
	if err := c.ensureOwned(ctx, req.ApplicationObjectID); err != nil {
		return protocol.AzureSecretResult{}, err
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || len(name) > 120 {
		return protocol.AzureSecretResult{}, errors.New("display_name is required and must be at most 120 characters")
	}
	expiresAt := req.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		expiresAt = c.now().UTC().Add(90 * 24 * time.Hour)
	}
	if !expiresAt.After(c.now().UTC()) {
		return protocol.AzureSecretResult{}, errors.New("expires_at must be in the future")
	}
	body := map[string]any{"passwordCredential": map[string]any{
		"displayName": name,
		"endDateTime": expiresAt.Format(time.RFC3339),
	}}
	var credential graphPasswordCredential
	path := "/applications/" + url.PathEscape(req.ApplicationObjectID) + "/addPassword"
	if err := c.graphJSONRetry(ctx, 8, transientGraph404, http.MethodPost, path, body, &credential); err != nil {
		return protocol.AzureSecretResult{}, err
	}
	if credential.SecretText == "" {
		_ = c.RemoveSecret(ctx, req.ApplicationObjectID, credential.KeyID)
		return protocol.AzureSecretResult{}, errors.New("Microsoft Graph returned no one-time secretText; credential was rolled back when possible")
	}
	result := protocol.AzureSecretResult{
		Credential: credential.toProtocol(),
		SecretText: credential.SecretText,
		OneTime:    true,
	}
	if vaultConfig != nil {
		vault := c.vaultClient()
		if vault == nil {
			return protocol.AzureSecretResult{}, errors.New("vault configuration was supplied but the vault client is unavailable")
		}
		ref, err := vault.Store(ctx, req.ApplicationObjectID, credential.KeyID, credential.SecretText, credential.EndDateTime, vaultConfig.OwnerObjectIDs)
		if err != nil {
			_ = c.RemoveSecret(ctx, req.ApplicationObjectID, credential.KeyID)
			return protocol.AzureSecretResult{}, fmt.Errorf("store credential in Key Vault (Graph credential was rolled back when possible): %w", err)
		}
		result.SecretText = ""
		result.OneTime = false
		result.Vault = &ref
	}
	return result, nil
}

// ReadSecret retrieves a secret from Key Vault, never from Graph or Redis.
func (c *AzureClient) ReadSecret(ctx context.Context, req protocol.AzureSecretReadRequest) (protocol.AzureSecretResult, error) {
	if err := c.ensureOwned(ctx, req.ApplicationObjectID); err != nil {
		return protocol.AzureSecretResult{}, err
	}
	vault := c.vaultClient()
	if vault == nil {
		return protocol.AzureSecretResult{}, errors.New("no Key Vault was configured for this session")
	}
	value, ref, err := vault.Read(ctx, req.ApplicationObjectID, req.KeyID, req.Version)
	if err != nil {
		return protocol.AzureSecretResult{}, err
	}
	return protocol.AzureSecretResult{SecretText: value, OneTime: true, Vault: &ref, Credential: protocol.AzureCredential{KeyID: req.KeyID, Vault: &ref}}, nil
}

// RemoveSecret invalidates a Graph password credential after ownership has
// been checked. Vault material is not returned; the Graph credential is the
// provider-side authority for whether the value can authenticate.
func (c *AzureClient) RemoveSecret(ctx context.Context, applicationObjectID, keyID string) error {
	if err := c.ensureOwned(ctx, applicationObjectID); err != nil {
		return err
	}
	if !guidPattern.MatchString(keyID) {
		return errors.New("key_id must be a GUID")
	}
	body := map[string]string{"keyId": keyID}
	path := "/applications/" + url.PathEscape(applicationObjectID) + "/removePassword"
	return c.graphJSONRetry(ctx, 8, transientPasswordReplication, http.MethodPost, path, body, nil)
}

// InvalidateSecret revokes Graph authentication and, when configured, disables
// the corresponding current Key Vault version. Graph revocation succeeds even
// if the vault update fails; callers receive the vault error explicitly.
func (c *AzureClient) InvalidateSecret(ctx context.Context, req protocol.AzureSecretInvalidateRequest) (protocol.AzureCredential, error) {
	if err := c.RemoveSecret(ctx, req.ApplicationObjectID, req.KeyID); err != nil {
		return protocol.AzureCredential{}, err
	}
	credential := protocol.AzureCredential{KeyID: req.KeyID}
	vault := c.vaultClient()
	if vault != nil {
		ref, err := vault.Disable(ctx, req.ApplicationObjectID, req.KeyID, req.Version)
		if err != nil {
			return credential, fmt.Errorf("Graph credential invalidated but Key Vault version could not be disabled: %w", err)
		}
		credential.Vault = &ref
	}
	return credential, nil
}

func (c *AzureClient) ensureOwned(ctx context.Context, objectID string) error {
	if !guidPattern.MatchString(objectID) {
		return errors.New("application_object_id must be a GUID")
	}
	owned, err := c.isOwned(ctx, objectID)
	if err != nil {
		return err
	}
	if !owned {
		return errors.New("application is not owned by the calling client; Application.ReadWrite.OwnedBy forbids this operation")
	}
	return nil
}

func (c *AzureClient) isOwned(ctx context.Context, objectID string) (bool, error) {
	c.mu.Lock()
	_, sessionCreated := c.createdObjects[objectID]
	c.mu.Unlock()
	if sessionCreated {
		// Session creation grant: applications created by this session are
		// owned by this session. App-only flows cannot attach the calling
		// service principal as an owner through Graph, so the session grant is
		// the honest ownership record; it never covers other tenants' apps.
		return true, nil
	}
	var response graphOwnerCollection
	path := "/applications/" + url.PathEscape(objectID) + "/owners?$select=id"
	if err := c.graphJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, owner := range response.Value {
		if _, ok := c.callingObjectIDs[owner.ID]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (c *AzureClient) token(ctx context.Context, scope string) (string, error) {
	now := c.now().UTC()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", errors.New("Azure integration session has expired")
	}
	if cached, ok := c.tokens[scope]; ok && cached.expiresAt.After(now.Add(30*time.Second)) {
		c.mu.Unlock()
		return cached.value, nil
	}
	secret := c.clientSecret
	c.mu.Unlock()
	if secret == "" {
		return "", errors.New("Azure integration session has expired")
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {secret},
		"scope":         {scope},
		"grant_type":    {"client_credentials"},
	}
	endpoint := strings.TrimSuffix(c.loginBaseURL, "/") + "/" + url.PathEscape(c.tenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", redactError(err.Error(), secret)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", redactError(err.Error(), secret)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Azure token endpoint returned HTTP %d: %s", response.StatusCode, redactError(strings.TrimSpace(string(data)), secret))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("decode Azure token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("Azure token endpoint returned no access token: %s", redactError(payload.Description, secret))
	}
	expires := now.Add(time.Duration(payload.ExpiresIn) * time.Second)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", errors.New("Azure integration session has expired")
	}
	c.tokens[scope] = accessToken{value: payload.AccessToken, expiresAt: expires}
	c.mu.Unlock()
	return payload.AccessToken, nil
}

// waitForApplication polls a freshly created application until the directory
// replica serving this session observes it. Microsoft Entra replicates writes
// asynchronously and can transiently answer 404 (Request_ResourceNotFound) for
// seconds after creation; addPassword/removePassword then fail even though the
// object is real. Bounded and best-effort: on timeout the following mutation
// retry (graphJSONRetry) carries the real error.
func (c *AzureClient) waitForApplication(ctx context.Context, objectID string) {
	const attempts = 12
	const pause = 750 * time.Millisecond
	var target graphApplication
	for i := 0; i < attempts; i++ {
		if err := c.graphJSON(ctx, http.MethodGet, "/applications/"+url.PathEscape(objectID)+"?$select=id", nil, &target); err == nil {
			return
		}
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return
		}
	}
}

// graphAPIError describes a Graph HTTP failure. It is typed so transient
// directory replication 404s can be retried without re-parsing messages.
type graphAPIError struct {
	StatusCode int
	Method     string
	Path       string
	Detail     string
}

func (e *graphAPIError) Error() string {
	return fmt.Sprintf("Microsoft Graph %s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Detail)
}

// transientGraph404 reports whether err is a Graph HTTP 404 such as the
// async-replication Request_ResourceNotFound seen right after directory writes.
func transientGraph404(err error) bool {
	var apiErr *graphAPIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// transientPasswordReplication extends transientGraph404 with the write-after-
// write 400 ("No password credential found with keyId") observed when
// removePassword races an addPassword that has not replicated yet. Retrying
// removal is idempotent and safe.
func transientPasswordReplication(err error) bool {
	if transientGraph404(err) {
		return true
	}
	var apiErr *graphAPIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest && strings.Contains(apiErr.Detail, "No password credential found with keyId")
}

// graphJSONRetry retries transient directory replication responses
// (see transientGraph404/transientPasswordReplication). Ident predicates with
// caller-chosen, idempotent re-issuance; non-matching failures surface
// immediately.
func (c *AzureClient) graphJSONRetry(ctx context.Context, attempts int, retryable func(error) bool, method, path string, body any, output any) error {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		lastErr = c.graphJSON(ctx, method, path, body, output)
		if lastErr == nil {
			return nil
		}
		if retryable == nil || !retryable(lastErr) {
			return lastErr
		}
		select {
		case <-time.After(700 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}

func (c *AzureClient) graphJSON(ctx context.Context, method, path string, body any, output any) error {
	token, err := c.token(ctx, "https://graph.microsoft.com/.default")
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
	req, err := http.NewRequestWithContext(ctx, method, c.graphBaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	secret := c.secretSnapshot()
	response, err := c.httpClient.Do(req)
	if err != nil {
		return redactError(err.Error(), secret, token)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return redactError(err.Error(), secret, token)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &graphAPIError{
			StatusCode: response.StatusCode,
			Method:     method,
			Path:       path,
			Detail:     redactError(strings.TrimSpace(string(data)), secret, token).Error(),
		}
	}
	if output == nil || response.StatusCode == http.StatusNoContent || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Microsoft Graph response: %w", err)
	}
	return nil
}

func (c *AzureClient) secretSnapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientSecret
}

func (c *AzureClient) vaultClient() *KeyVaultClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vault
}

func redactError(value string, secrets ...string) error {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return errors.New(value)
}

type graphServicePrincipal struct {
	ID string `json:"id"`
}

type graphOwnerCollection struct {
	Value []struct {
		ID string `json:"id"`
	} `json:"value"`
}

type graphApplicationCollection struct {
	Value []graphApplication `json:"value"`
}

type graphApplication struct {
	ID                  string                    `json:"id"`
	AppID               string                    `json:"appId"`
	DisplayName         string                    `json:"displayName"`
	CreatedDateTime     time.Time                 `json:"createdDateTime"`
	PasswordCredentials []graphPasswordCredential `json:"passwordCredentials"`
}

type graphPasswordCredential struct {
	KeyID         string    `json:"keyId"`
	DisplayName   string    `json:"displayName"`
	SecretText    string    `json:"secretText"`
	StartDateTime time.Time `json:"startDateTime"`
	EndDateTime   time.Time `json:"endDateTime"`
	Hint          string    `json:"hint"`
}

func (a graphApplication) toProtocol(owned bool) protocol.AzureApplication {
	credentials := make([]protocol.AzureCredential, 0, len(a.PasswordCredentials))
	for _, credential := range a.PasswordCredentials {
		credentials = append(credentials, credential.toProtocol())
	}
	return protocol.AzureApplication{ObjectID: a.ID, ApplicationID: a.AppID, DisplayName: a.DisplayName, CreatedAt: a.CreatedDateTime, OwnedByCallingClient: owned, Credentials: credentials}
}

func (c graphPasswordCredential) toProtocol() protocol.AzureCredential {
	return protocol.AzureCredential{KeyID: c.KeyID, DisplayName: c.DisplayName, StartAt: c.StartDateTime, ExpiresAt: c.EndDateTime, Hint: c.Hint}
}
