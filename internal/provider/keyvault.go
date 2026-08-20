package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// KeyVaultClient is an Azure Key Vault data-plane client used only by an
// ephemeral AzureClient. The caller must grant the client ID an appropriate
// Key Vault data-plane role; Graph permissions do not grant vault access.
type KeyVaultClient struct {
	baseURL      string
	secretPrefix string
	azure        *AzureClient
	httpClient   *http.Client
	now          func() time.Time
}

// NewKeyVaultClient validates an existing vault URL. Mutandae never creates a
// vault or role assignment and never accepts a non-HTTPS vault endpoint.
func NewKeyVaultClient(config protocol.VaultConfiguration, azure *AzureClient, httpClient *http.Client, now func() time.Time) (*KeyVaultClient, error) {
	if azure == nil {
		return nil, errors.New("Azure client is required for Key Vault")
	}
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(config.URL), "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("vault.url must be an HTTPS Azure Key Vault URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".vault.azure.net") {
		return nil, errors.New("vault.url must use an Azure Key Vault host ending in .vault.azure.net without credentials, query, or fragment")
	}
	prefix := strings.Trim(config.SecretPrefix, "-/ ")
	if prefix == "" {
		prefix = "mutandae"
	}
	if !prefixPattern.MatchString(prefix) {
		return nil, errors.New("vault.secret_prefix must contain only letters, numbers, and hyphens")
	}
	for _, owner := range config.OwnerObjectIDs {
		if !guidPattern.MatchString(owner) {
			return nil, errors.New("vault.owner_object_ids must contain only GUIDs")
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &KeyVaultClient{baseURL: parsed.String(), secretPrefix: prefix, azure: azure, httpClient: httpClient, now: now}, nil
}

// Store writes a new versioned Key Vault secret and returns only its redacted
// reference. Owner IDs are stored as tags for operators; actual owner-only
// read enforcement must be provided by Azure RBAC/delegated identity outside
// this client because a client-credential token has no human requester.
func (v *KeyVaultClient) Store(ctx context.Context, applicationObjectID, keyID, value string, expiresAt time.Time, ownerObjectIDs []string) (protocol.VaultReference, error) {
	if !guidPattern.MatchString(applicationObjectID) || !guidPattern.MatchString(keyID) {
		return protocol.VaultReference{}, errors.New("application and credential identifiers must be GUIDs")
	}
	if value == "" {
		return protocol.VaultReference{}, errors.New("cannot store an empty secret")
	}
	name := v.secretName(applicationObjectID, keyID)
	tags := map[string]string{
		"mutandaeApplicationObjectId": applicationObjectID,
		"mutandaeKeyId":               keyID,
		"mutandaeExpiresAt":           expiresAt.UTC().Format(time.RFC3339),
	}
	if len(ownerObjectIDs) > 0 {
		tags["mutandaeOwnerObjectIds"] = strings.Join(ownerObjectIDs, ",")
	}
	body := map[string]any{
		"value":       value,
		"contentType": "mutandae-client-secret",
		"attributes":  map[string]any{"enabled": true, "exp": expiresAt.UTC().Unix()},
		"tags":        tags,
	}
	var response keyVaultSecret
	if err := v.request(ctx, http.MethodPut, "/secrets/"+url.PathEscape(name), body, &response); err != nil {
		return protocol.VaultReference{}, err
	}
	version := response.Version
	if version == "" {
		version = versionFromID(response.ID)
	}
	return protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: version, ExpiresAt: expiresAt.UTC(), OwnerObjectIDs: append([]string(nil), ownerObjectIDs...)}, nil
}

// Disable invalidates the current version of a stored secret. Key Vault does
// not support deleting an individual version, so this uses the documented
// versioned PATCH operation and leaves the vault's retention/audit policy
// intact.
func (v *KeyVaultClient) Disable(ctx context.Context, applicationObjectID, keyID, version string) (protocol.VaultReference, error) {
	if !guidPattern.MatchString(applicationObjectID) || !guidPattern.MatchString(keyID) {
		return protocol.VaultReference{}, errors.New("application and credential identifiers must be GUIDs")
	}
	name := v.secretName(applicationObjectID, keyID)
	if version != "" && !regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`).MatchString(version) {
		return protocol.VaultReference{}, errors.New("vault version is invalid")
	}
	current := keyVaultSecret{Version: version}
	if current.Version == "" {
		if err := v.request(ctx, http.MethodGet, "/secrets/"+url.PathEscape(name), nil, &current); err != nil {
			return protocol.VaultReference{}, err
		}
		if current.Version == "" {
			current.Version = versionFromID(current.ID)
		}
	}
	if current.Version == "" {
		return protocol.VaultReference{}, errors.New("Key Vault did not return a secret version")
	}
	if err := v.requestVersion(ctx, http.MethodPatch, "/secrets/"+url.PathEscape(name)+"/"+url.PathEscape(current.Version), map[string]any{"attributes": map[string]any{"enabled": false}}, nil); err != nil {
		return protocol.VaultReference{}, err
	}
	expiresAt := time.Time{}
	if raw := current.Tags["mutandaeExpiresAt"]; raw != "" {
		expiresAt, _ = time.Parse(time.RFC3339, raw)
	}
	return protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: current.Version, ExpiresAt: expiresAt, OwnerObjectIDs: splitOwners(current.Tags["mutandaeOwnerObjectIds"])}, nil
}

// Read retrieves a versioned secret. The caller must separately arrange
// owner-only access using Key Vault RBAC or delegated authorization.
func (v *KeyVaultClient) Read(ctx context.Context, applicationObjectID, keyID, version string) (string, protocol.VaultReference, error) {
	if !guidPattern.MatchString(applicationObjectID) || !guidPattern.MatchString(keyID) {
		return "", protocol.VaultReference{}, errors.New("application and credential identifiers must be GUIDs")
	}
	name := v.secretName(applicationObjectID, keyID)
	path := "/secrets/" + url.PathEscape(name)
	if version != "" {
		if !regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`).MatchString(version) {
			return "", protocol.VaultReference{}, errors.New("vault version is invalid")
		}
		path += "/" + url.PathEscape(version)
	}
	var response keyVaultSecret
	if err := v.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return "", protocol.VaultReference{}, err
	}
	if response.Value == "" {
		return "", protocol.VaultReference{}, errors.New("Key Vault returned an empty secret")
	}
	expiresAt := time.Time{}
	if raw := response.Tags["mutandaeExpiresAt"]; raw != "" {
		expiresAt, _ = time.Parse(time.RFC3339, raw)
	}
	owners := splitOwners(response.Tags["mutandaeOwnerObjectIds"])
	ref := protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: response.Version, ExpiresAt: expiresAt, OwnerObjectIDs: owners}
	return response.Value, ref, nil
}

func (v *KeyVaultClient) secretName(applicationObjectID, keyID string) string {
	name := v.secretPrefix + "-" + strings.ToLower(applicationObjectID) + "-" + strings.ToLower(keyID)
	if len(name) > 127 {
		name = name[:127]
	}
	return name
}

func (v *KeyVaultClient) request(ctx context.Context, method, path string, body any, output *keyVaultSecret) error {
	return v.requestVersion(ctx, method, path, body, output)
}

func (v *KeyVaultClient) requestVersion(ctx context.Context, method, path string, body any, output *keyVaultSecret) error {
	token, err := v.azure.token(ctx, "https://vault.azure.net/.default")
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(payload))
	}
	endpoint := v.baseURL + path + "?api-version=" + url.QueryEscape(azureVaultAPI)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	secret := v.azure.secretSnapshot()
	response, err := v.httpClient.Do(req)
	if err != nil {
		return redactError(err.Error(), secret, token)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return redactError(err.Error(), secret, token)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Azure Key Vault %s %s returned HTTP %d: %s", method, path, response.StatusCode, redactError(strings.TrimSpace(string(data)), secret, token))
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Azure Key Vault response: %w", err)
	}
	return nil
}

type keyVaultSecret struct {
	ID      string            `json:"id"`
	Version string            `json:"version"`
	Value   string            `json:"value"`
	Tags    map[string]string `json:"tags"`
}

func versionFromID(id string) string {
	parts := strings.Split(strings.TrimRight(id, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	candidate := parts[len(parts)-1]
	if regexp.MustCompile(`^[0-9a-fA-F]{32}$`).MatchString(candidate) {
		return candidate
	}
	return ""
}

func splitOwners(value string) []string {
	if value == "" {
		return nil
	}
	items := strings.Split(value, ",")
	owners := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if guidPattern.MatchString(item) {
			owners = append(owners, item)
		}
	}
	return owners
}
