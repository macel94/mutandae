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
	"strconv"
	"strings"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// HashiCorp Vault KV v2 delivery. This file is provider-neutral on purpose:
// HashiCorp Vault is not tied to one cloud, so the store speaks the same
// CloudVault boundary as the native AWS/GCP/Azure vaults and is wired at the
// composition root like any other delivery target.
//
// Trust boundary (mirrors awssecrets.go / gcpsecret.go): the secret value is
// sent only inside the authenticated request body and is returned only from
// ReadSecret. References, names, and versions are safe to persist. Errors are
// redacted — they never contain the secret, the Vault token, or the raw
// response body — so they are safe to persist into audit events.

const (
	// vaultDefaultMount is the KV v2 mount used when Mount is empty. This is
	// Vault's conventional "secret" KV v2 mount.
	vaultDefaultMount = "secret"
	// vaultDefaultPrefix is the demo path prefix used when Prefix is empty.
	vaultDefaultPrefix = "mutandae"
	// vaultDefaultTimeout bounds one Vault HTTP round trip when no client is
	// injected. Operators may inject a client with their own timeouts.
	vaultDefaultTimeout = 10 * time.Second
	// vaultMaxResponseBytes caps how much of a Vault response is read into
	// memory. Secret payloads in the demo are tiny; the cap only bounds abuse.
	vaultMaxResponseBytes = 1 << 20
	// vaultErrorDetailMax bounds the redacted detail quoted from a Vault error
	// response so audit lines stay short no matter what the server returns.
	vaultErrorDetailMax = 200
	// vaultSegmentMax bounds one sanitized path segment (identity name or
	// key id) regardless of what the caller supplied.
	vaultSegmentMax = 63
	// vaultDefaultTTL is the displayed validity window stamped into returned
	// references when the operator configures no explicit TTL. KV v2 itself
	// never expires secrets; the TTL only feeds the demo's ExpiresAt metadata.
	vaultDefaultTTL = 24 * time.Hour
)

// ErrVaultSecretNotFound is returned when the vault reports HTTP 404 for a
// read of a secret path or version. It is distinguishable from other failures
// so callers can treat "already gone" as a terminal, non-alarming state.
var ErrVaultSecretNotFound = errors.New("hashicorp vault: secret not found")

// HashiCorpVaultConfig is the composition-root configuration for the Vault KV
// v2 store. The token is a Vault service token; it is never logged, never
// persisted, and never included in an error message.
type HashiCorpVaultConfig struct {
	// Addr is the Vault server base address, for example
	// "https://vault.internal:8200". Plain http is accepted so tests and local
	// dev clusters (and this package's own httptest fake) can reach it.
	Addr string
	// Token is the Vault token sent as X-Vault-Token on every request. Required.
	Token string
	// Mount is the KV v2 mount name. Defaults to "secret".
	Mount string
	// Prefix is the demo namespace prefix inside the mount. Defaults to
	// "mutandae".
	Prefix string
	// Now is the injected clock. When nil, time.Now is used. Tests inject a
	// fixed clock so ExpiresAt assertions are deterministic.
	Now func() time.Time
	// TTL is the validity window stamped into returned references as
	// ExpiresAt = Now() + TTL. Defaults to 24 hours.
	TTL time.Duration
	// HTTPClient is the injected HTTP client. When nil, a client with a 10s
	// total timeout is constructed.
	HTTPClient *http.Client
}

// HashiCorpVault delivers machine-identity credentials to a HashiCorp Vault
// KV v2 mount over its plain JSON HTTP API (no SDK). It implements CloudVault.
type HashiCorpVault struct {
	addr       string
	token      string
	mount      string
	prefix     string
	now        func() time.Time
	ttl        time.Duration
	httpClient *http.Client
}

// Compile-time proof the store satisfies the provider-neutral vault boundary.
var _ CloudVault = (*HashiCorpVault)(nil)

// NewHashiCorpVault validates the configuration and returns a KV v2 store.
// Validation errors are returned, never panicked: a misconfigured vault is a
// runtime configuration problem, not a programmer error.
func NewHashiCorpVault(config HashiCorpVaultConfig) (*HashiCorpVault, error) {
	addr := strings.TrimRight(strings.TrimSpace(config.Addr), "/")
	parsed, err := url.Parse(addr)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		if err == nil {
			err = errors.New("addr must be an absolute URL without credentials, query, or fragment")
		}
		return nil, fmt.Errorf("hashicorp vault: invalid addr: %v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("hashicorp vault: addr scheme %q is not supported; use http or https", parsed.Scheme)
	}
	token := strings.TrimSpace(config.Token)
	if token == "" {
		return nil, errors.New("hashicorp vault: token is required")
	}
	mount := config.Mount
	if mount == "" {
		mount = vaultDefaultMount
	}
	if !vaultSegmentAllowed(mount) {
		return nil, errors.New("hashicorp vault: mount is not a valid path segment")
	}
	prefix := config.Prefix
	if prefix == "" {
		prefix = vaultDefaultPrefix
	}
	if !vaultPrefixAllowed(prefix) {
		return nil, errors.New("hashicorp vault: prefix is not a valid path prefix")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	ttl := config.TTL
	if ttl <= 0 {
		ttl = vaultDefaultTTL
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: vaultDefaultTimeout}
	}
	return &HashiCorpVault{addr: addr, token: token, mount: mount, prefix: prefix, now: now, ttl: ttl, httpClient: httpClient}, nil
}

// StoreSecret writes a new version of the identity's credential as
// {"data":{"secret":...}} at <mount>/data/<prefix>/<identity>/<keyID>. KV v2
// versions automatically; every store produces a new immutable version whose
// number is echoed in the response metadata.
func (v *HashiCorpVault) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	if err := ctx.Err(); err != nil {
		return protocol.VaultReference{}, err
	}
	path, effectiveKeyID, err := v.vaultPath(identity, keyID)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	var response struct {
		Data struct {
			Version   int  `json:"version"`
			Destroyed bool `json:"destroyed"`
		} `json:"data"`
	}
	// The KV v2 payload keeps the secret under the documented "secret" key
	// alongside redacted-safe audit fields: who owns it, which key and
	// provider it belongs to, and when Mutandae stored it. None of these
	// fields is credential material, so references stay persistable.
	payload := map[string]any{
		"data": map[string]string{
			"secret":    secret,
			"key_id":    effectiveKeyID,
			"provider":  identity.Provider.Provider,
			"identity":  identity.Name,
			"stored_at": v.now().UTC().Format(time.RFC3339),
		},
	}
	if err := v.request(ctx, http.MethodPost, v.mount+"/data/"+path, payload, &response, secret); err != nil {
		return protocol.VaultReference{}, err
	}
	return protocol.VaultReference{
		URL:        v.addr,
		SecretName: v.mount + "/" + path,
		Version:    vaultVersionString(response.Data.Version),
		ExpiresAt:  v.expiresAt(),
	}, nil
}

// ReadSecret retrieves the current or pinned version of the identity's
// credential. The KV v2 read response nests the payload one level deeper than
// the write request: {"data":{"data":{...},"metadata":{"version":N,...}}}.
// The secret value crosses this boundary only as the successful return value.
func (v *HashiCorpVault) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	if err := ctx.Err(); err != nil {
		return "", protocol.VaultReference{}, err
	}
	path, _, err := v.vaultPath(identity, keyID)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}
	apiPath := v.mount + "/data/" + path
	switch version {
	case "", "current", "latest":
		// Omit the query parameter: KV v2 returns the current version.
	default:
		if _, convErr := strconv.Atoi(version); convErr != nil {
			return "", protocol.VaultReference{}, errors.New("hashicorp vault: secret version is invalid")
		}
		apiPath += "?version=" + url.QueryEscape(version)
	}
	var response struct {
		Data struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				Version   int  `json:"version"`
				Destroyed bool `json:"destroyed"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := v.request(ctx, http.MethodGet, apiPath, nil, &response, ""); err != nil {
		return "", protocol.VaultReference{}, err
	}
	if response.Data.Metadata.Destroyed {
		return "", protocol.VaultReference{}, fmt.Errorf("%w: version is destroyed", ErrVaultSecretNotFound)
	}
	raw, ok := response.Data.Data["secret"]
	if !ok {
		return "", protocol.VaultReference{}, errors.New("hashicorp vault: response contains no secret value")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", protocol.VaultReference{}, errors.New("hashicorp vault: response secret value is malformed")
	}
	return value, protocol.VaultReference{
		URL:        v.addr,
		SecretName: v.mount + "/" + path,
		Version:    vaultVersionString(response.Data.Metadata.Version),
		ExpiresAt:  v.expiresAt(),
	}, nil
}

// RevokeSecret removes all versions and metadata of the identity's credential
// by deleting the KV v2 metadata path. The operation is idempotent: HTTP 404
// means the secret is already gone, which is the desired end state, so both
// outcomes return the redacted reference with no version pinned.
func (v *HashiCorpVault) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	if err := ctx.Err(); err != nil {
		return protocol.VaultReference{}, err
	}
	path, _, err := v.vaultPath(identity, keyID)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	// Deleting metadata is idempotent: HTTP 404 means the secret is already
	// gone, which is the desired end state, so the not-found classification is
	// swallowed and the redacted reference is returned either way.
	if err := v.request(ctx, http.MethodDelete, v.mount+"/metadata/"+path, nil, nil, ""); err != nil && !errors.Is(err, ErrVaultSecretNotFound) {
		return protocol.VaultReference{}, err
	}
	return protocol.VaultReference{
		URL:        v.addr,
		SecretName: v.mount + "/" + path,
	}, nil
}

// request performs one Vault JSON API call. Status mapping:
//   - 2xx: decode into output when present.
//   - 404: ErrVaultSecretNotFound (distinguishable via errors.Is).
//   - 501/503: "Vault is sealed or unavailable (HTTP %d)" — Vault's documented
//     uninitialized/sealed statuses.
//   - anything else: a redacted error carrying the status and a truncated
//     detail taken only from the parsed "errors" field — never the raw body.
//
// The optional secret is scrubbed from every message; the token is scrubbed
// from every message unconditionally.
func (v *HashiCorpVault) request(ctx context.Context, method, apiPath string, payload any, output any, secret string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return v.redactedError("hashicorp vault: encode request: "+err.Error(), secret)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.addr+"/v1/"+apiPath, body)
	if err != nil {
		return v.redactedError("hashicorp vault: create request: "+err.Error(), secret)
	}
	if v.token != "" {
		req.Header.Set("X-Vault-Token", v.token)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := v.httpClient.Do(req)
	if err != nil {
		message := v.redactedString("hashicorp vault: request failed: "+err.Error(), secret)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%s: %w", message, err)
		}
		return errors.New(message)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, vaultMaxResponseBytes))
	if err != nil {
		message := v.redactedString("hashicorp vault: read response: "+err.Error(), secret)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%s: %w", message, err)
		}
		return errors.New(message)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return v.apiError(response.StatusCode, data, secret)
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return v.redactedError("hashicorp vault: decode response: "+err.Error(), secret)
	}
	return nil
}

// apiError maps a non-2xx Vault status onto the error contract. The message
// is built from fixed text plus, for unexpected statuses, a bounded detail
// parsed from the body's "errors" field. The raw body is never quoted.
func (v *HashiCorpVault) apiError(status int, body []byte, secret string) error {
	switch status {
	case http.StatusNotFound:
		return fmt.Errorf("%w (HTTP 404)", ErrVaultSecretNotFound)
	case http.StatusNotImplemented, http.StatusServiceUnavailable:
		return fmt.Errorf("Vault is sealed or unavailable (HTTP %d)", status)
	default:
		detail := v.vaultErrorDetail(body, secret)
		return v.redactedError(fmt.Sprintf("HashiCorp Vault returned HTTP %d: %s", status, detail), secret)
	}
}

// vaultErrorDetail extracts a truncated, redacted detail string from a Vault
// error body. Only the parsed "errors" strings are used; when the body is not
// a recognizable Vault error the detail withholds the body entirely.
func (v *HashiCorpVault) vaultErrorDetail(body []byte, secret string) string {
	var payload struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || len(payload.Errors) == 0 {
		return "(response body withheld)"
	}
	// Scrub before truncation so a token or secret partially surviving the
	// cut can never leak; the "[redacted]" marker is safe to truncate.
	detail := v.redactedString(strings.Join(payload.Errors, "; "), secret)
	return vaultTruncate(detail)
}

// redactedString removes the caller's secret and the Vault token from an
// error message, mirroring awsRedactedError, so messages are safe to persist
// into audit events.
func (v *HashiCorpVault) redactedString(value, secret string) string {
	if secret != "" {
		value = strings.ReplaceAll(value, secret, "[redacted]")
	}
	if v.token != "" {
		value = strings.ReplaceAll(value, v.token, "[redacted]")
	}
	return value
}

// redactedError builds a redacted error from a message string.
func (v *HashiCorpVault) redactedError(value, secret string) error {
	return errors.New(v.redactedString(value, secret))
}

// expiresAt stamps the reference validity window from the injected clock so
// tests and deployments stay deterministic.
func (v *HashiCorpVault) expiresAt() time.Time {
	return v.now().UTC().Add(v.ttl)
}

// vaultPath derives and validates the secret path below the mount:
// <prefix>/<sanitized identity>. Like the AWS and GCP vaults, rotations write
// new versions under one auditable per-identity secret — the key id lives in
// the stored payload, never in the path — so revocation removes every version
// of the credential at once. Access is refused outside the mutandae-demo-*
// namespace before any sanitization, keeping the demo trust boundary anchored
// to the true name.
func (v *HashiCorpVault) vaultPath(identity protocol.MachineIdentity, keyID string) (string, string, error) {
	if !isDemoName(identity.Name) {
		return "", "", fmt.Errorf("hashicorp vault: refusing vault access outside the %s* namespace", demoPrefix)
	}
	name := vaultSanitizeSegment(identity.Name)
	if name == "" {
		return "", "", errors.New("hashicorp vault: demo identity name sanitizes to an empty path segment")
	}
	effectiveKeyID := keyID
	if effectiveKeyID == "" {
		effectiveKeyID = "current"
	}
	return v.prefix + "/" + name, effectiveKeyID, nil
}

// vaultSanitizeSegment maps a wire-provided name onto a Vault-safe path
// segment: characters outside [A-Za-z0-9_-] become '-', leading and trailing
// dashes are trimmed, and the result is capped at vaultSegmentMax characters.
func vaultSanitizeSegment(value string) string {
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '-', char == '_':
			builder.WriteRune(char)
		default:
			builder.WriteByte('-')
		}
	}
	sanitized := strings.Trim(builder.String(), "-")
	if len(sanitized) > vaultSegmentMax {
		sanitized = strings.Trim(sanitized[:vaultSegmentMax], "-")
	}
	return sanitized
}

// vaultSegmentAllowed reports whether s is a single, URL-safe path segment:
// letters, digits, dot, underscore, and dash only, with no "." or "..".
func vaultSegmentAllowed(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if s == "." || s == ".." {
		return false
	}
	for _, char := range s {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// vaultPrefixAllowed validates a multi-segment prefix such as "mutandae" or
// "mutandae/team-a". Empty segments are rejected so the derived path never
// contains "//".
func vaultPrefixAllowed(prefix string) bool {
	if prefix == "" || len(prefix) > 512 {
		return false
	}
	for _, segment := range strings.Split(prefix, "/") {
		if !vaultSegmentAllowed(segment) {
			return false
		}
	}
	return true
}

// vaultVersionString renders a numeric KV v2 version, or "" when the server
// did not report one.
func vaultVersionString(version int) string {
	if version <= 0 {
		return ""
	}
	return strconv.Itoa(version)
}

// vaultTruncate bounds a redacted detail string to vaultErrorDetailMax bytes.
func vaultTruncate(detail string) string {
	if len(detail) <= vaultErrorDetailMax {
		return detail
	}
	return detail[:vaultErrorDetailMax] + "..."
}
