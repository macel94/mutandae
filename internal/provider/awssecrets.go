package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

const awsSecretsManagerService = "secretsmanager"

// awsSecretsManagerResponse contains the safe metadata returned by the
// Secrets Manager JSON API. SecretString is populated only for GetSecretValue.
// Store and Revoke never return it to the caller.
type awsSecretsManagerResponse struct {
	ARN          string `json:"ARN"`
	Name         string `json:"Name"`
	VersionID    string `json:"VersionId"`
	SecretString string `json:"SecretString"`
}

type awsSecretsManagerTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// awsSecretsManagerAPIError retains the HTTP status and provider error code so
// Store can distinguish a missing secret from other failures without exposing
// the response body or any credential material.
type awsSecretsManagerAPIError struct {
	status           int
	code             string
	detail           string
	resourceNotFound bool
	unauthorized     bool
}

func (e *awsSecretsManagerAPIError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("AWS Secrets Manager returned HTTP %d: %s", e.status, e.detail)
	}
	return fmt.Sprintf("AWS Secrets Manager returned HTTP %d (%s): %s", e.status, e.code, e.detail)
}

// StoreSecret writes the identity's credential as a new Secrets Manager
// version. The deterministic name keeps rotations under one auditable secret;
// the existing demo namespace is the trust boundary for this capability.
func (a *AWSAdapter) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	if !a.secretsManager {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	name, effectiveKeyID, err := a.awsSecretName(identity, keyID)
	if err != nil {
		return protocol.VaultReference{}, a.awsRedactedError(err.Error(), secret)
	}

	payload := map[string]string{
		"SecretId":     name,
		"SecretString": secret,
	}
	var response awsSecretsManagerResponse
	if err := a.secretsRequest(ctx, "PutSecretValue", payload, &response, secret); err != nil {
		if awsSecretsManagerDenied(err) {
			return protocol.VaultReference{}, fmt.Errorf("%w: AWS Secrets Manager denied the credential write", ErrVaultUnsupported)
		}
		if !awsSecretsManagerResourceNotFound(err) {
			return protocol.VaultReference{}, err
		}

		createPayload := map[string]any{
			"Name":         name,
			"SecretString": secret,
			"Description":  "Mutandae demo credential",
			"Tags": []awsSecretsManagerTag{
				{Key: "MutandaeIdentity", Value: identity.Name},
				{Key: "MutandaeKeyId", Value: effectiveKeyID},
				{Key: "MutandaeProvider", Value: identity.Provider.Provider},
			},
		}
		if err := a.secretsRequest(ctx, "CreateSecret", createPayload, nil, secret); err != nil {
			if awsSecretsManagerDenied(err) {
				return protocol.VaultReference{}, fmt.Errorf("%w: AWS Secrets Manager denied the credential write", ErrVaultUnsupported)
			}
			return protocol.VaultReference{}, err
		}
		// CreateSecret creates the initial version, but the PutSecretValue retry
		// makes the write path converge on the same versioning operation as a
		// previously-created secret.
		if err := a.secretsRequest(ctx, "PutSecretValue", payload, &response, secret); err != nil {
			if awsSecretsManagerDenied(err) {
				return protocol.VaultReference{}, fmt.Errorf("%w: AWS Secrets Manager denied the credential write", ErrVaultUnsupported)
			}
			return protocol.VaultReference{}, err
		}
	}

	return protocol.VaultReference{
		URL:        a.awsSecretsManagerEndpointBase(),
		SecretName: name,
		Version:    response.VersionID,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

// ReadSecret retrieves the current or requested version of the identity's
// credential from Secrets Manager. Secret material crosses the boundary only
// in this read result; references remain safe to persist.
func (a *AWSAdapter) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	if !a.secretsManager {
		return "", protocol.VaultReference{}, ErrVaultUnsupported
	}
	name, _, err := a.awsSecretName(identity, keyID)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}

	payload := map[string]string{"SecretId": name}
	if version != "" && version != "current" {
		payload["VersionId"] = version
	} else {
		payload["VersionStage"] = "AWSCURRENT"
	}
	var response awsSecretsManagerResponse
	if err := a.secretsRequest(ctx, "GetSecretValue", payload, &response); err != nil {
		if awsSecretsManagerDenied(err) {
			return "", protocol.VaultReference{}, fmt.Errorf("%w: AWS Secrets Manager denied the credential read", ErrVaultUnsupported)
		}
		return "", protocol.VaultReference{}, err
	}
	if response.SecretString == "" {
		return "", protocol.VaultReference{}, a.redact("GetSecretValue returned no SecretString")
	}
	return response.SecretString, protocol.VaultReference{
		URL:        a.awsSecretsManagerEndpointBase(),
		SecretName: name,
		Version:    response.VersionID,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

// RevokeSecret schedules deletion of the identity's Secrets Manager secret
// with the provider's seven-day recovery window. A missing secret is already
// revoked and therefore succeeds idempotently.
func (a *AWSAdapter) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	if !a.secretsManager {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	name, _, err := a.awsSecretName(identity, keyID)
	if err != nil {
		return protocol.VaultReference{}, err
	}

	payload := map[string]any{
		"SecretId":             name,
		"RecoveryWindowInDays": 7,
	}
	if err := a.secretsRequest(ctx, "DeleteSecret", payload, nil); err != nil {
		if awsSecretsManagerDenied(err) {
			return protocol.VaultReference{}, fmt.Errorf("%w: AWS Secrets Manager denied the credential revocation", ErrVaultUnsupported)
		}
		if !awsSecretsManagerResourceNotFound(err) {
			return protocol.VaultReference{}, err
		}
	}
	return protocol.VaultReference{
		URL:        a.awsSecretsManagerEndpointBase(),
		SecretName: name,
		ExpiresAt:  identity.ExpiresAt,
	}, nil
}

// awsSecretName derives the deterministic Secrets Manager name and validates
// it against the service's ASCII character set and 512-byte maximum.
func (a *AWSAdapter) awsSecretName(identity protocol.MachineIdentity, keyID string) (string, string, error) {
	if !isDemoName(identity.Name) {
		return "", "", a.redact(fmt.Sprintf("aws: refusing vault access outside the %s* namespace", demoPrefix))
	}
	effectiveKeyID := keyID
	if effectiveKeyID == "" {
		effectiveKeyID = "current"
	}
	name := "mutandae-demo/" + identity.Name + "/" + effectiveKeyID
	if len(name) > 512 || !awsSecretsManagerNameAllowed(name) {
		return "", "", a.redact("aws: derived Secrets Manager secret name is invalid")
	}
	return name, effectiveKeyID, nil
}

func awsSecretsManagerNameAllowed(name string) bool {
	if name == "" || len(name) > 512 {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			strings.ContainsRune("/_+=.@-", char) {
			continue
		}
		return false
	}
	return true
}

func (a *AWSAdapter) awsSecretsManagerEndpointBase() string {
	endpoint := a.secretsEndpoint
	if endpoint == "" {
		endpoint = "https://secretsmanager." + a.region + ".amazonaws.com/"
	}
	return strings.TrimRight(endpoint, "/")
}

// secretsRequest performs one Secrets Manager JSON API call with SigV4. The
// optional redactions cover a write-only StoreSecret value that is not part of
// AWSAdapter's long-lived credential snapshot.
func (a *AWSAdapter) secretsRequest(ctx context.Context, operation string, payload any, output any, extraRedactions ...string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return a.awsRedactedError(fmt.Sprintf("%s: encode request: %v", operation, err), extraRedactions...)
	}
	endpoint, err := url.Parse(a.awsSecretsManagerEndpointBase())
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		if err == nil {
			err = errors.New("endpoint must be an absolute URL without credentials, query, or fragment")
		}
		return a.awsRedactedError(fmt.Sprintf("%s: invalid Secrets Manager endpoint: %v", operation, err), extraRedactions...)
	}

	amzDate := a.now().UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	host := endpoint.Host
	canonicalURI := endpoint.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	target := awsSecretsManagerService + "." + operation

	// These names and values are sorted exactly as required by SigV4. Unlike
	// IAM, Secrets Manager is regional, so the operator region is used for both
	// official amazonaws.com hosts and custom/test endpoints.
	canonicalHeaders := "content-type:application/x-amz-json-1.1\nhost:" + host + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"
	if a.sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + a.sessionToken + "\n"
		signedHeaders += ";x-amz-security-token"
	}
	canonicalHeaders += "x-amz-target:" + target + "\n"
	signedHeaders += ";x-amz-target"
	scope := strings.Join([]string{dateStamp, a.region, awsSecretsManagerService, "aws4_request"}, "/")
	signature := signV4(sigV4Options{
		method:           http.MethodPost,
		canonicalURI:     canonicalURI,
		canonicalHeaders: canonicalHeaders,
		signedHeaders:    signedHeaders,
		payloadHash:      sha256Hex(body),
		amzDate:          amzDate,
		scope:            scope,
		secretKey:        a.secretKey,
	})
	authorization := "AWS4-HMAC-SHA256 Credential=" + a.accessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return a.awsRedactedError(fmt.Sprintf("%s: create request: %v", operation, err), extraRedactions...)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authorization)
	if a.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", a.sessionToken)
	}

	response, err := a.httpClient.Do(req)
	if err != nil {
		message := a.awsRedactedString(fmt.Sprintf("%s: request failed: %v", operation, err), extraRedactions...)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%s: %w", a.redact(message), err)
		}
		return a.redact(message)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		message := a.awsRedactedString(fmt.Sprintf("%s: read response: %v", operation, err), extraRedactions...)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%s: %w", a.redact(message), err)
		}
		return a.redact(message)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return a.awsSecretsManagerAPIError(operation, response.StatusCode, data, extraRedactions...)
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return a.awsRedactedError(fmt.Sprintf("%s: decode response: %v", operation, err), extraRedactions...)
	}
	return nil
}

func (a *AWSAdapter) awsSecretsManagerAPIError(operation string, status int, data []byte, extraRedactions ...string) error {
	var payload struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &payload)
	code := strings.TrimSpace(payload.Type)
	if payload.Code != "" {
		if code != "" {
			code += " " + strings.TrimSpace(payload.Code)
		} else {
			code = strings.TrimSpace(payload.Code)
		}
	}
	detail := strings.TrimSpace(payload.Message)
	if detail == "" {
		detail = strings.TrimSpace(string(data))
	}
	if detail == "" {
		detail = "(empty response)"
	}
	return &awsSecretsManagerAPIError{
		status:           status,
		code:             a.awsRedactedString(code, extraRedactions...),
		detail:           a.awsRedactedString(fmt.Sprintf("%s: %s", operation, detail), extraRedactions...),
		resourceNotFound: status == http.StatusNotFound && strings.Contains(code, "ResourceNotFoundException"),
		// Secrets Manager reports authorization failures as AccessDenied*
		// (observed on HTTP 400) or as plain HTTP 403. A deterministic denial
		// means the wired credentials were never granted the vault capability,
		// which the adapter treats as "unsupported in practice".
		unauthorized: status == http.StatusForbidden || strings.Contains(code, "AccessDenied"),
	}
}

func awsSecretsManagerResourceNotFound(err error) bool {
	var apiErr *awsSecretsManagerAPIError
	return errors.As(err, &apiErr) && apiErr.resourceNotFound
}

// awsSecretsManagerDenied reports whether Secrets Manager rejected the call
// because the caller is not authorized. Mapping the denial onto the canonical
// ErrVaultUnsupported sentinel keeps the demo honest and quiet: provision
// delivery skips instead of spamming failure events, and credential reads
// fall back to the cluster μVault copy.
func awsSecretsManagerDenied(err error) bool {
	var apiErr *awsSecretsManagerAPIError
	return errors.As(err, &apiErr) && apiErr.unauthorized
}

func (a *AWSAdapter) awsRedactedString(value string, extra ...string) string {
	value = a.redactString(value)
	for _, secret := range extra {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func (a *AWSAdapter) awsRedactedError(value string, extra ...string) error {
	return a.redact(a.awsRedactedString(value, extra...))
}
