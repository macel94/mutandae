package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

const (
	// gcpSecretIDPattern is the Secret Manager secret-id character set and
	// limit. The demo identity name is used directly so the provider namespace
	// remains visible in the vault without introducing another mapping.
	gcpSecretIDPattern = `^[a-zA-Z0-9_-]{1,255}$`
	// gcpSecretVersionPattern accepts numeric Secret Manager versions and
	// version aliases. The latest alias is handled as an ordinary valid alias.
	gcpSecretVersionPattern = `^[a-zA-Z0-9_-]{1,255}$`
)

type gcpSecretVersion struct {
	Name string `json:"name"`
}

type gcpSecretAccessResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"`
	} `json:"payload"`
}

// StoreSecret writes a new version of the identity's credential into GCP
// Secret Manager. Secret Manager is deliberately used as an existing
// provider data-plane boundary: the adapter creates only the deterministic
// demo secret when an add-version call reports that it is absent.
//
// Trust boundary: the secret value is sent only in the authenticated request
// body and is never included in a VaultReference or a returned error.
func (a *GCPAdapter) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	if !a.secretManager {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	if err := ctx.Err(); err != nil {
		return protocol.VaultReference{}, err
	}
	name, err := gcpVaultSecretName(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}

	body := map[string]any{
		"payload": map[string]string{
			"data": base64.StdEncoding.EncodeToString([]byte(secret)),
		},
	}
	path := a.gcpSecretAddVersionPath(name)
	var response gcpSecretVersion
	err = a.iamJSON(ctx, http.MethodPost, path, body, &response)
	if err != nil && gcpVaultDenied(err) {
		return protocol.VaultReference{}, fmt.Errorf("%w: GCP Secret Manager denied the credential write", ErrVaultUnsupported)
	}
	if err != nil && gcpVaultNotFound(err) {
		createBody := map[string]any{
			"replication": map[string]any{
				"automatic": map[string]any{},
			},
			"labels": map[string]string{
				"mutandae": "demo",
			},
		}
		createPath := a.gcpSecretCreatePath(name)
		if createErr := a.iamJSON(ctx, http.MethodPost, createPath, createBody, nil); createErr != nil {
			if gcpVaultDenied(createErr) {
				return protocol.VaultReference{}, fmt.Errorf("%w: GCP Secret Manager denied the credential write", ErrVaultUnsupported)
			}
			return protocol.VaultReference{}, a.redactGCPVaultError(ctx, createErr, secret)
		}
		// POST mutations are intentionally not retried by iamJSON. This is the
		// single explicit retry after creating a previously absent secret.
		response = gcpSecretVersion{}
		err = a.iamJSON(ctx, http.MethodPost, path, body, &response)
	}
	if err != nil {
		if gcpVaultDenied(err) {
			return protocol.VaultReference{}, fmt.Errorf("%w: GCP Secret Manager denied the credential write", ErrVaultUnsupported)
		}
		return protocol.VaultReference{}, a.redactGCPVaultError(ctx, err, secret)
	}
	version, err := gcpVaultVersion(response.Name)
	if err != nil {
		return protocol.VaultReference{}, a.redactGCPVaultError(ctx, err, secret)
	}
	return protocol.VaultReference{
		URL:        a.secretBaseURL,
		SecretName: name,
		Version:    version,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

// ReadSecret retrieves the current or requested version of the identity's
// credential from Secret Manager and decodes its standard-base64 payload.
// The secret value crosses this boundary only as the successful return value.
func (a *GCPAdapter) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	if !a.secretManager {
		return "", protocol.VaultReference{}, ErrVaultUnsupported
	}
	if err := ctx.Err(); err != nil {
		return "", protocol.VaultReference{}, err
	}
	name, err := gcpVaultSecretName(identity)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}
	if version == "" {
		version = "latest"
	}
	if !gcpVaultValueMatches(gcpSecretVersionPattern, version) {
		return "", protocol.VaultReference{}, errors.New("gcp: Secret Manager version is invalid")
	}

	var response gcpSecretAccessResponse
	path := a.gcpSecretAccessPath(name, version)
	if err := a.iamJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		if gcpVaultDenied(err) {
			return "", protocol.VaultReference{}, fmt.Errorf("%w: GCP Secret Manager denied the credential read", ErrVaultUnsupported)
		}
		return "", protocol.VaultReference{}, a.redactGCPVaultError(ctx, err, "")
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Payload.Data)
	if err != nil {
		return "", protocol.VaultReference{}, a.redactGCPVaultError(ctx, errors.New("gcp: decode Secret Manager payload: "+err.Error()), "")
	}
	resolvedVersion, err := gcpVaultVersion(response.Name)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}
	return string(decoded), protocol.VaultReference{
		URL:        a.secretBaseURL,
		SecretName: name,
		Version:    resolvedVersion,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

// RevokeSecret disables the current Secret Manager version. A missing secret
// is already revoked from Mutandae's perspective, making retirement
// idempotent when a prior cleanup or an external operator removed it.
func (a *GCPAdapter) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	if !a.secretManager {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	if err := ctx.Err(); err != nil {
		return protocol.VaultReference{}, err
	}
	name, err := gcpVaultSecretName(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}

	var response gcpSecretVersion
	path := a.gcpSecretDisablePath(name)
	if err := a.iamJSON(ctx, http.MethodPost, path, nil, &response); err != nil {
		if gcpVaultDenied(err) {
			return protocol.VaultReference{}, fmt.Errorf("%w: GCP Secret Manager denied the credential revocation", ErrVaultUnsupported)
		}
		if gcpVaultNotFound(err) {
			return protocol.VaultReference{
				URL:        a.secretBaseURL,
				SecretName: name,
				Version:    "latest",
				ExpiresAt:  identity.ExpiresAt,
			}, nil
		}
		return protocol.VaultReference{}, a.redactGCPVaultError(ctx, err, "")
	}
	resolvedVersion := "latest"
	if response.Name != "" {
		resolvedVersion, err = gcpVaultVersion(response.Name)
		if err != nil {
			return protocol.VaultReference{}, err
		}
	}
	return protocol.VaultReference{
		URL:        a.secretBaseURL,
		SecretName: name,
		Version:    resolvedVersion,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

func gcpVaultSecretName(identity protocol.MachineIdentity) (string, error) {
	if !isDemoName(identity.Name) {
		return "", fmt.Errorf("gcp: refusing vault access outside the %s* namespace", demoPrefix)
	}
	// GCP identity names are service-account emails ("name@project.iam.
	// gserviceaccount.com"), but Secret Manager secret ids only allow
	// [a-zA-Z0-9_-]. Sanitize deterministically — the same identity always
	// maps to the same secret, keeping rotations under one auditable secret —
	// instead of refusing delivery for every real provisioned identity.
	name := gcpSanitizeSecretID(identity.Name)
	if name == "" {
		return "", errors.New("gcp: demo identity name sanitizes to an empty Secret Manager secret id")
	}
	return name, nil
}

// gcpSanitizeSecretID maps a wire-provided name onto a Secret Manager secret
// id: characters outside [A-Za-z0-9_-] become '-', leading and trailing '-'
// are trimmed, and the result is capped at 255 characters.
func gcpSanitizeSecretID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 255 {
		id = id[:255]
	}
	return id
}

func (a *GCPAdapter) gcpSecretAddVersionPath(name string) string {
	return a.secretBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/secrets/" + url.PathEscape(name) + ":addVersion"
}

func (a *GCPAdapter) gcpSecretCreatePath(name string) string {
	return a.secretBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/secrets?secretId=" + url.QueryEscape(name)
}

func (a *GCPAdapter) gcpSecretAccessPath(name, version string) string {
	return a.secretBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/secrets/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version) + ":access"
}

func (a *GCPAdapter) gcpSecretDisablePath(name string) string {
	return a.secretBaseURL + "/projects/" + url.PathEscape(a.projectID) + "/secrets/" + url.PathEscape(name) + "/versions/latest:disable"
}

func gcpVaultValueMatches(pattern, value string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

func gcpVaultVersion(resourceName string) (string, error) {
	index := strings.LastIndex(resourceName, "/")
	if index < 0 || index+1 >= len(resourceName) {
		return "", errors.New("gcp: Secret Manager returned an incomplete version name")
	}
	version := resourceName[index+1:]
	if !gcpVaultValueMatches(gcpSecretVersionPattern, version) {
		return "", errors.New("gcp: Secret Manager returned an invalid version name")
	}
	return version, nil
}

// gcpVaultNotFound classifies only the status forms emitted by iamJSON's
// Google error formatter, allowing the caller to distinguish a missing secret
// from permission and transport failures without changing shared IAM plumbing.
func gcpVaultNotFound(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "returned HTTP 404") ||
		strings.Contains(text, "returned NOT_FOUND (404)") ||
		strings.Contains(text, "returned  (404)")
}

// gcpVaultDenied reports whether Secret Manager rejected the call because the
// caller is not authorized (HTTP 403 / PERMISSION_DENIED). A deterministic
// denial means the wired service account was never granted the Secret Manager
// capability, so the adapter reports the canonical ErrVaultUnsupported:
// delivery skips silently and reads fall back to the cluster μVault copy.
func gcpVaultDenied(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "returned HTTP 403") ||
		strings.Contains(text, "returned  (403)") ||
		strings.Contains(text, "PERMISSION_DENIED")
}

// redactGCPVaultError preserves context cancellation and removes both the
// cleartext and wire-encoded secret from errors returned by shared GCP code.
func (a *GCPAdapter) redactGCPVaultError(ctx context.Context, err error, secret string) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	message := err.Error()
	for _, value := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret))} {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	a.mu.Lock()
	accessToken := a.accessToken
	a.mu.Unlock()
	if accessToken != "" {
		message = strings.ReplaceAll(message, accessToken, "[redacted]")
	}
	return a.redact(message)
}
