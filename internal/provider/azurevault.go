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

// azureDemoVault delivers scoped credentials into an existing Azure Key Vault.
// It is the azure-entra implementation of the CloudVault capability: every
// provisioned or renewed in-scope client secret is written as a new Key Vault
// secret version, and every use reads the versioned value back.
//
// Trust boundary: the vault must already exist and the governor application
// must already hold the Key Vault data-plane role (see docs/live-demo.md);
// Mutandae never creates a vault or a role assignment. Secret values are
// write-only on Store and returned only from Read; references, names, versions,
// and tags are safe to persist. The client secret held by the AzureClient is
// write-only and redacted from every error.
type azureDemoVault struct {
	baseURL      string
	secretPrefix string
	azure        *AzureClient
	httpClient   *http.Client
	now          func() time.Time
	scope        Scope
}

// azureVaultNamePattern is the Key Vault secret-name character set
// ([0-9a-zA-Z-], up to 127 characters).
var azureVaultNamePattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)

// azureVersionPattern matches a Key Vault secret version id.
var azureVersionPattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

// newAzureDemoVault validates an existing vault URL and returns the vault
// capability bound to the governor's AzureClient (which mints the
// https://vault.azure.net/.default tokens).
func newAzureDemoVault(vaultURL, secretPrefix string, scope Scope, azure *AzureClient, httpClient *http.Client, now func() time.Time) (*azureDemoVault, error) {
	if azure == nil {
		return nil, errors.New("azure: Azure client is required for Key Vault delivery")
	}
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(vaultURL), "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("azure: vault URL must be an HTTPS Azure Key Vault URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".vault.azure.net") {
		return nil, errors.New("azure: vault URL must use an Azure Key Vault host ending in .vault.azure.net without credentials, query, or fragment")
	}
	prefix := strings.Trim(secretPrefix, "-/ ")
	if prefix == "" {
		prefix = "mutandae"
	}
	if !prefixPattern.MatchString(prefix) {
		return nil, errors.New("azure: vault secret prefix must contain only letters, numbers, and hyphens")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &azureDemoVault{baseURL: parsed.String(), secretPrefix: prefix, scope: scope, azure: azure, httpClient: httpClient, now: now}, nil
}

// StoreSecret writes the credential as a new version of the identity's vault
// secret. The deterministic name is derived from the demo identity name, so a
// rotation lands as a new version of the same secret.
func (v *azureDemoVault) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	name, err := v.secretName(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	if strings.TrimSpace(secret) == "" {
		return protocol.VaultReference{}, errors.New("azure: cannot store an empty secret")
	}
	expiresAt := identity.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = v.now().UTC().Add(90 * 24 * time.Hour)
	}
	body := map[string]any{
		"value":       secret,
		"contentType": "mutandae-demo-credential",
		"attributes":  map[string]any{"enabled": true, "exp": expiresAt.UTC().Unix()},
		"tags": map[string]string{
			"mutandaeIdentity":   identity.Name,
			"mutandaeProvider":   identity.Provider.Provider,
			"mutandaeKeyId":      keyID,
			"mutandaeExpiresAt":  expiresAt.UTC().Format(time.RFC3339),
			"mutandaeProviderID": identity.Provider.ProviderID,
		},
	}
	var response keyVaultSecret
	if err := v.request(ctx, http.MethodPut, "/secrets/"+url.PathEscape(name), body, &response); err != nil {
		return protocol.VaultReference{}, err
	}
	version := response.Version
	if version == "" {
		version = versionFromID(response.ID)
	}
	return protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: version, ExpiresAt: expiresAt.UTC()}, nil
}

// ReadSecret retrieves the current (or pinned) version of the credential.
func (v *azureDemoVault) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	name, err := v.secretName(identity)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}
	if version != "" && !azureVersionPattern.MatchString(version) {
		return "", protocol.VaultReference{}, errors.New("azure: vault version is invalid")
	}
	path := "/secrets/" + url.PathEscape(name)
	if version != "" {
		path += "/" + url.PathEscape(version)
	}
	var response keyVaultSecret
	if err := v.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return "", protocol.VaultReference{}, err
	}
	if response.Value == "" {
		return "", protocol.VaultReference{}, errors.New("azure: Key Vault returned an empty secret")
	}
	expiresAt := time.Time{}
	if raw := response.Tags["mutandaeExpiresAt"]; raw != "" {
		expiresAt, _ = time.Parse(time.RFC3339, raw)
	}
	ref := protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: response.Version, ExpiresAt: expiresAt}
	return response.Value, ref, nil
}

// RevokeSecret disables the current version of the identity's vault secret.
// Key Vault does not support deleting an individual version, so revocation
// follows the documented versioned PATCH disable operation.
func (v *azureDemoVault) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	name, err := v.secretName(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	current := keyVaultSecret{}
	if err := v.request(ctx, http.MethodGet, "/secrets/"+url.PathEscape(name), nil, &current); err != nil {
		return protocol.VaultReference{}, err
	}
	version := current.Version
	if version == "" {
		version = versionFromID(current.ID)
	}
	if version == "" {
		return protocol.VaultReference{}, errors.New("azure: Key Vault did not return a secret version")
	}
	if err := v.requestVersion(ctx, http.MethodPatch, "/secrets/"+url.PathEscape(name)+"/"+url.PathEscape(version), map[string]any{"attributes": map[string]any{"enabled": false}}, nil); err != nil {
		return protocol.VaultReference{}, err
	}
	return protocol.VaultReference{URL: v.baseURL, SecretName: name, Version: version}, nil
}

// secretName derives the deterministic Key Vault secret name for a demo
// identity and validates it against the Key Vault character set.
func (v *azureDemoVault) secretName(identity protocol.MachineIdentity) (string, error) {
	if strings.TrimSpace(identity.Name) == "" || !v.scope.Match(identity.Name) {
		return "", forbiddenScopeError(azureKind, identity.Name, v.scope)
	}
	name := v.secretPrefix + "-" + strings.ToLower(identity.Name)
	name = strings.Trim(name, "-")
	if len(name) > 127 {
		name = name[:127]
	}
	if !azureVaultNamePattern.MatchString(name) {
		return "", errors.New("azure: derived Key Vault secret name is invalid")
	}
	return name, nil
}

// request performs one vault data-plane call with a governor token for the
// https://vault.azure.net/.default scope. Errors are redacted against the
// write-only client secret.
func (v *azureDemoVault) request(ctx context.Context, method, path string, body any, output *keyVaultSecret) error {
	return v.requestVersion(ctx, method, path, body, output)
}

func (v *azureDemoVault) requestVersion(ctx context.Context, method, path string, body any, output *keyVaultSecret) error {
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
