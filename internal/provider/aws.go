package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
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

// awsKind ("aws-iam") is declared in awssimulator.go and shared by the real
// adapter so both implementations produce identical ProviderBindings.

const (
	awsIAMVersion = "2010-05-08"
	awsIAMService = "iam"
)

// AWSAdapterConfig carries the connection material for a real AWS IAM adapter.
// The long-lived access key is write-only: it is accepted by the constructor,
// used to sign requests, and never returned by any method or placed into a
// protocol object.
type AWSAdapterConfig struct {
	// AccountID is the 12-digit AWS account that owns the governed IAM users.
	AccountID string
	// Region is the operator's default region. IAM is a global service, so
	// signatures always use the global IAM signing scope (see signingRegion).
	Region string
	// AccessKeyID / SecretKey are the evaluation principal's credentials.
	// SessionToken is optional and used only when the principal is assumed.
	AccessKeyID  string
	SecretKey    string
	SessionToken string
	// Endpoint overrides the IAM service endpoint (used by tests); the default
	// is the official global endpoint https://iam.amazonaws.com.
	Endpoint string
	// HTTPClient overrides the transport used for IAM calls.
	HTTPClient *http.Client
	// Now pins the provider clock for deterministic tests.
	Now func() time.Time
}

// AWSAdapter is a real AWS IAM adapter behind the CloudAdapter boundary. It
// speaks the IAM Query API directly with AWS Signature Version 4 using only
// the Go standard library; it never depends on an AWS SDK.
//
// Trust boundary: IAM returns an access key's secret only from CreateAccessKey
// and never again. The adapter keeps the freshly created secret in process
// memory purely for immediate one-time handoff to the operator
// (ConsumeOneTimeSecret) and clears it on the next rotation, on Close, or when
// consumed — it is never placed into a protocol object, event, snapshot, or
// log.
type AWSAdapter struct {
	accountID    string
	region       string
	accessKeyID  string
	secretKey    string
	sessionToken string
	endpoint     string
	httpClient   *http.Client
	now          func() time.Time

	mu             sync.Mutex
	oneTimeSecret  string
	oneTimeKeyID   string
	oneTimeCreated time.Time
}

// NewAWSAdapter validates connection material and returns a real IAM adapter.
// It does not contact AWS; discovery or the first mutation verifies access.
func NewAWSAdapter(cfg AWSAdapterConfig) (*AWSAdapter, error) {
	accountID := strings.TrimSpace(cfg.AccountID)
	if accountID == "" {
		return nil, errors.New("aws: account_id is required")
	}
	accessKeyID := strings.TrimSpace(cfg.AccessKeyID)
	if accessKeyID == "" {
		return nil, errors.New("aws: access key id is required")
	}
	if cfg.SecretKey == "" {
		return nil, errors.New("aws: secret access key is required")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &AWSAdapter{
		accountID:    accountID,
		region:       region,
		accessKeyID:  accessKeyID,
		secretKey:    cfg.SecretKey,
		sessionToken: cfg.SessionToken,
		endpoint:     endpoint,
		httpClient:   httpClient,
		now:          now,
	}, nil
}

// Kind returns the stable provider identifier.
func (a *AWSAdapter) Kind() string { return awsKind }

// ConsumeOneTimeSecret returns and clears the most recent one-time secret
// created by Rotate. The second call returns "". Nothing in the protocol ever
// carries this value; only an operator who captured it at rotation time can
// verify the delivered credential (for example by comparing the sha256 of the
// secret with the rotation evidence fingerprint, when fingerprints are derived
// from the delivered secret).
func (a *AWSAdapter) ConsumeOneTimeSecret() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	value := a.oneTimeSecret
	a.oneTimeSecret = ""
	a.oneTimeKeyID = ""
	return value
}

// OneTimeKeyID reports which access key the most recent one-time secret belongs
// to, without revealing the secret. It is cleared together with the secret.
func (a *AWSAdapter) OneTimeKeyID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.oneTimeKeyID
}

// Close clears secret material held for one-time handoff.
func (a *AWSAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secretKey = ""
	a.sessionToken = ""
	a.oneTimeSecret = ""
	a.oneTimeKeyID = ""
}

// Discover returns the provider's current view of machine identities: every
// IAM user that owns at least one access key. Governed expiry is approximated
// from the key create date plus the operator's renewal period because IAM
// access keys do not carry an expiry; the control plane remains authoritative
// for governance after adoption.
func (a *AWSAdapter) Discover(ctx context.Context) ([]protocol.MachineIdentity, error) {
	users, err := a.listUsers(ctx)
	if err != nil {
		return nil, err
	}
	identities := make([]protocol.MachineIdentity, 0, len(users))
	for _, user := range users {
		// IAM ListUsers does not return tags, but GetUser does. Ownership and
		// renewal metadata are stored as MUTANDAE_* tags (see
		// docs/aws-integration.md), so resolve each user with GetUser to map
		// ownership honestly.
		detail, err := a.getUser(ctx, user.UserName)
		if err != nil {
			return nil, fmt.Errorf("%s: user %q: %w", awsKind, user.UserName, err)
		}
		keys, err := a.listAccessKeys(ctx, user.UserName)
		if err != nil {
			return nil, fmt.Errorf("%s: user %q: %w", awsKind, user.UserName, err)
		}
		if len(keys) == 0 {
			continue // no renewable access credential; not governed by Mutandae
		}
		identities = append(identities, a.toIdentity(detail, keys))
	}
	return identities, nil
}

// iamUserRecord is the IAM user metadata the adapter maps into protocol
// ownership. Tag keys are documented in docs/aws-integration.md.
type iamUserRecord struct {
	Path       string    `xml:"Path"`
	UserName   string    `xml:"UserName"`
	UserID     string    `xml:"UserId"`
	ARN        string    `xml:"Arn"`
	CreateDate time.Time `xml:"CreateDate"`
	Tags       []iamTag  `xml:"Tags>member"`
}

type iamTag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type iamAccessKeyMetadata struct {
	UserName    string    `xml:"UserName"`
	AccessKeyID string    `xml:"AccessKeyId"`
	Status      string    `xml:"Status"`
	CreateDate  time.Time `xml:"CreateDate"`
}

// toIdentity builds a conformant MachineIdentity from a user and its keys.
// The newest active key is the identity's credential; if no key is active the
// newest key is used so a rotated-out-but-not-yet-deleted key still surfaces.
func (a *AWSAdapter) toIdentity(user iamUserRecord, keys []iamAccessKeyMetadata) protocol.MachineIdentity {
	sort.Slice(keys, func(i, j int) bool { return keys[i].CreateDate.After(keys[j].CreateDate) })
	key := keys[0]
	for _, candidate := range keys {
		if strings.EqualFold(candidate.Status, "Active") {
			key = candidate
			break
		}
	}
	tags := make(map[string]string, len(user.Tags))
	for _, tag := range user.Tags {
		tags[tag.Key] = tag.Value
	}
	renewalDays := tagInt(tags, "MUTANDAE_RENEWAL_DAYS", 90)
	renewal := time.Duration(renewalDays) * 24 * time.Hour
	expiresAt := key.CreateDate.Add(renewal)
	health := protocol.HealthHealthy
	if !a.now().UTC().Before(expiresAt) {
		health = protocol.HealthAttention
	}
	environment := tagValue(tags, "MUTANDAE_ENVIRONMENT", "production")
	contacts := tagList(tags, "MUTANDAE_CONTACTS")
	return protocol.MachineIdentity{
		Name:        user.UserName,
		DisplayName: user.UserName,
		Environment: environment,
		Provider: protocol.ProviderBinding{
			Provider:   awsKind,
			ProviderID: user.UserName,
			AccountID:  a.accountID,
			Region:     a.region,
		},
		Ownership: protocol.Ownership{
			Team:        tagValue(tags, "MUTANDAE_TEAM", "AWS IAM"),
			Service:     tagValue(tags, "MUTANDAE_SERVICE", user.UserName),
			Purpose:     tagValue(tags, "MUTANDAE_PURPOSE", "Machine workload identity"),
			Criticality: tagValue(tags, "MUTANDAE_CRITICALITY", "medium"),
			Contacts:    contacts,
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    protocol.FormatISO8601Duration(renewal),
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "access_key",
			Location:    "iam://" + a.accountID + "/user/" + user.UserName,
			Fingerprint: awsFingerprint(key.AccessKeyID),
			KeyID:       key.AccessKeyID,
			Delivery:    "secret-manager",
		},
		State:         protocol.StateActive,
		Health:        health,
		ExpiresAt:     expiresAt,
		LastRotatedAt: key.CreateDate,
	}
}

// awsFingerprint derives deterministic verification metadata from the provider
// key id. IAM exposes no fingerprint field; the digest lets the UI and audit
// trail show that rotation replaced the key while never touching secret
// material.
func awsFingerprint(keyID string) string {
	sum := sha256.Sum256([]byte(keyID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Rotate rotates the IAM user's access key under AWS's hard two-key ceiling:
// make room if needed, create the new key (capturing the one-time secret),
// then delete the rotated-out key. The returned evidence contains the new
// access key id and a deterministic digest; the secret itself is delivered
// once via ConsumeOneTimeSecret.
func (a *AWSAdapter) Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	userName := strings.TrimSpace(identity.Provider.ProviderID)
	if userName == "" {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: rotate requires a provider_id (IAM user name)", awsKind)
	}
	keys, err := a.listAccessKeys(ctx, userName)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if len(keys) == 0 {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: user %q has no access keys to rotate", awsKind, userName)
	}

	currentKeyID := strings.TrimSpace(identity.Credential.KeyID)
	current := findKey(keys, currentKeyID)
	if current == nil {
		sort.Slice(keys, func(i, j int) bool { return keys[i].CreateDate.After(keys[j].CreateDate) })
		current = &keys[0]
	}

	if len(keys) >= 2 {
		// At the two-key ceiling: delete a non-current key first so the create
		// below cannot be rejected by IAM's hard limit.
		remove := oldestNonCurrent(keys, current.AccessKeyID)
		if err := a.deleteAccessKey(ctx, userName, remove.AccessKeyID); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}

	created, err := a.createAccessKey(ctx, userName)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}

	// Rotate out the old key. Already deleted above (no-op tolerated).
	if current.AccessKeyID != created.AccessKeyID {
		if err := a.deleteAccessKey(ctx, userName, current.AccessKeyID); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}

	a.mu.Lock()
	a.oneTimeSecret = created.SecretAccessKey
	a.oneTimeKeyID = created.AccessKeyID
	a.oneTimeCreated = a.now().UTC()
	a.mu.Unlock()

	return a.toIdentity(iamUserRecord{UserName: userName}, []iamAccessKeyMetadata{{
		UserName:    userName,
		AccessKeyID: created.AccessKeyID,
		Status:      "Active",
		CreateDate:  created.CreateDate,
	}}), nil
}

// Retire decommissions the identity in IAM by deleting every access key the
// user owns and removing a console login profile when present. With all keys
// deleted the user is no longer rediscovered, matching the simulator contract.
func (a *AWSAdapter) Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	userName := strings.TrimSpace(identity.Provider.ProviderID)
	if userName == "" {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: retire requires a provider_id (IAM user name)", awsKind)
	}
	keys, err := a.listAccessKeys(ctx, userName)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	for _, key := range keys {
		if err := a.deleteAccessKey(ctx, userName, key.AccessKeyID); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}
	// Best-effort: DeleteLoginProfile is optional in the documented policy and
	// NoSuchEntity simply means the user had no console password.
	_ = a.deleteLoginProfile(ctx, userName)
	view := identity
	view.State = protocol.StateRetired
	view.Health = protocol.HealthAttention
	view.Credential = protocol.CredentialReference{
		Kind:     "access_key",
		Location: "iam://" + a.accountID + "/user/" + userName,
		Delivery: "secret-manager",
	}
	return view, nil
}

// --- IAM Query API plumbing (AWS Signature Version 4) ---

func findKey(keys []iamAccessKeyMetadata, keyID string) *iamAccessKeyMetadata {
	for i := range keys {
		if keyID != "" && keys[i].AccessKeyID == keyID {
			return &keys[i]
		}
	}
	return nil
}

func oldestNonCurrent(keys []iamAccessKeyMetadata, currentKeyID string) *iamAccessKeyMetadata {
	var oldest *iamAccessKeyMetadata
	for i := range keys {
		if keys[i].AccessKeyID == currentKeyID {
			continue
		}
		if oldest == nil || keys[i].CreateDate.Before(oldest.CreateDate) {
			copy := keys[i]
			oldest = &copy
		}
	}
	if oldest != nil {
		return oldest
	}
	oldest = &keys[0]
	for i := range keys {
		if keys[i].CreateDate.Before(oldest.CreateDate) {
			oldest = &keys[i]
		}
	}
	return oldest
}

func (a *AWSAdapter) listUsers(ctx context.Context) ([]iamUserRecord, error) {
	var users []iamUserRecord
	marker := ""
	for {
		params := url.Values{"Action": {"ListUsers"}, "Version": {awsIAMVersion}}
		if marker != "" {
			params.Set("Marker", marker)
		}
		var response struct {
			Users       []iamUserRecord `xml:"ListUsersResult>Users>member"`
			IsTruncated bool            `xml:"ListUsersResult>IsTruncated"`
			Marker      string          `xml:"ListUsersResult>Marker"`
		}
		if err := a.call(ctx, params, &response); err != nil {
			return nil, err
		}
		users = append(users, response.Users...)
		if !response.IsTruncated || response.Marker == "" {
			break
		}
		marker = response.Marker
		if len(users) > 10000 {
			return nil, fmt.Errorf("%s: ListUsers pagination exceeded a sane bound", awsKind)
		}
	}
	return users, nil
}

// getUser returns the caller-visible details for one IAM user, including its
// MUTANDAE_* tags which ListUsers deliberately omits.
func (a *AWSAdapter) getUser(ctx context.Context, userName string) (iamUserRecord, error) {
	params := url.Values{"Action": {"GetUser"}, "Version": {awsIAMVersion}, "UserName": {userName}}
	var response struct {
		User iamUserRecord `xml:"GetUserResult>User"`
	}
	if err := a.call(ctx, params, &response); err != nil {
		return iamUserRecord{}, err
	}
	return response.User, nil
}

func (a *AWSAdapter) listAccessKeys(ctx context.Context, userName string) ([]iamAccessKeyMetadata, error) {
	params := url.Values{"Action": {"ListAccessKeys"}, "Version": {awsIAMVersion}, "UserName": {userName}}
	var response struct {
		Keys        []iamAccessKeyMetadata `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
		IsTruncated bool                   `xml:"ListAccessKeysResult>IsTruncated"`
		Marker      string                 `xml:"ListAccessKeysResult>Marker"`
	}
	if err := a.call(ctx, params, &response); err != nil {
		return nil, err
	}
	return response.Keys, nil
}

type iamAccessKey struct {
	UserName        string    `xml:"UserName"`
	AccessKeyID     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	Status          string    `xml:"Status"`
	CreateDate      time.Time `xml:"CreateDate"`
}

func (a *AWSAdapter) createAccessKey(ctx context.Context, userName string) (iamAccessKey, error) {
	params := url.Values{"Action": {"CreateAccessKey"}, "Version": {awsIAMVersion}, "UserName": {userName}}
	var response struct {
		AccessKey iamAccessKey `xml:"CreateAccessKeyResult>AccessKey"`
	}
	if err := a.call(ctx, params, &response); err != nil {
		return iamAccessKey{}, err
	}
	key := response.AccessKey
	if key.AccessKeyID == "" || key.SecretAccessKey == "" {
		return iamAccessKey{}, fmt.Errorf("%s: CreateAccessKey returned an incomplete response", awsKind)
	}
	return key, nil
}

func (a *AWSAdapter) deleteAccessKey(ctx context.Context, userName, keyID string) error {
	if keyID == "" {
		return nil
	}
	params := url.Values{"Action": {"DeleteAccessKey"}, "Version": {awsIAMVersion}, "UserName": {userName}, "AccessKeyId": {keyID}}
	return a.tolerateNoSuchEntity(ctx, params)
}

func (a *AWSAdapter) deleteLoginProfile(ctx context.Context, userName string) error {
	params := url.Values{"Action": {"DeleteLoginProfile"}, "Version": {awsIAMVersion}, "UserName": {userName}}
	return a.tolerateNoSuchEntity(ctx, params)
}

// call signs and executes one IAM Query API call and decodes the XML result.
func (a *AWSAdapter) call(ctx context.Context, params url.Values, output any) error {
	action := params.Get("Action")
	body := params.Encode()
	req, err := a.signedRequest(ctx, body)
	if err != nil {
		return err
	}
	response, err := a.httpClient.Do(req)
	if err != nil {
		return a.redact(fmt.Sprintf("%s: request failed: %v", action, err))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return a.redact(fmt.Sprintf("%s: read response: %v", action, err))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return a.iamError(action, data, response.StatusCode)
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	if err := xml.Unmarshal(data, output); err != nil {
		return a.redact(fmt.Sprintf("%s: decode response: %v", action, err))
	}
	return nil
}

func (a *AWSAdapter) tolerateNoSuchEntity(ctx context.Context, params url.Values) error {
	action := params.Get("Action")
	body := params.Encode()
	req, err := a.signedRequest(ctx, body)
	if err != nil {
		return err
	}
	response, err := a.httpClient.Do(req)
	if err != nil {
		return a.redact(fmt.Sprintf("%s: request failed: %v", action, err))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return a.redact(fmt.Sprintf("%s: read response: %v", action, err))
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	var errorResponse iamErrorResponse
	if err := xml.Unmarshal(data, &errorResponse); err == nil && errorResponse.Code == "NoSuchEntity" {
		return nil
	}
	return a.iamError(action, data, response.StatusCode)
}

func (a *AWSAdapter) iamError(action string, data []byte, status int) error {
	var errorResponse iamErrorResponse
	if err := xml.Unmarshal(data, &errorResponse); err == nil && errorResponse.Code != "" {
		message := a.redactString(errorResponse.Message)
		return fmt.Errorf("%s: IAM returned %s: %s", action, errorResponse.Code, message)
	}
	decoded := strings.TrimSpace(string(data))
	if decoded == "" {
		decoded = "(empty response)"
	}
	return a.redact(fmt.Sprintf("%s: IAM returned HTTP %d: %s", action, status, decoded))
}

type iamErrorResponse struct {
	Type      string `xml:"Error>Type"`
	Code      string `xml:"Error>Code"`
	Message   string `xml:"Error>Message"`
	RequestID string `xml:"RequestId"`
}

// signedRequest builds the POST form request and signs it with AWS Signature
// Version 4 using the standard library. IAM is a global service: the
// credential scope always uses the account partition's global signing region
// (us-east-1 for the standard endpoint).
func (a *AWSAdapter) signedRequest(ctx context.Context, body string) (*http.Request, error) {
	endpoint, err := url.Parse(a.endpoint)
	if err != nil {
		return nil, fmt.Errorf("aws: invalid IAM endpoint %q: %w", a.endpoint, err)
	}
	amzDate := a.now().UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	host := endpoint.Host

	// SigV4 requires the canonical URI to start with a forward slash. The
	// official IAM endpoint uses an empty path, which normalizes to "/".
	canonicalURI := endpoint.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalHeaders := "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:" + host + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"
	if a.sessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + a.sessionToken + "\n"
		signedHeaders += ";x-amz-security-token"
	}

	signingRegion := "us-east-1"
	if !strings.Contains(host, "amazonaws.com") {
		// Custom/test endpoint: keep the operator's region in the scope so a
		// record-keeping mock can rely on it.
		signingRegion = a.region
	}
	scope := strings.Join([]string{dateStamp, signingRegion, awsIAMService, "aws4_request"}, "/")
	signature := signV4(sigV4Options{
		method:           http.MethodPost,
		canonicalURI:     canonicalURI,
		canonicalHeaders: canonicalHeaders,
		signedHeaders:    signedHeaders,
		payloadHash:      sha256Hex([]byte(body)),
		amzDate:          amzDate,
		scope:            scope,
		secretKey:        a.secretKey,
	})

	authorization := "AWS4-HMAC-SHA256 Credential=" + a.accessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authorization)
	if a.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", a.sessionToken)
	}
	return req, nil
}

// sigV4Options is the parameterization of the AWS Signature Version 4
// algorithm. The IAM adapter fills it from its POST form request; the unit
// test drives it with the official AWS test suite vectors.
type sigV4Options struct {
	method           string
	canonicalURI     string
	canonicalHeaders string
	signedHeaders    string
	payloadHash      string
	amzDate          string
	scope            string // datestamp/region/service/aws4_request
	secretKey        string
}

// signV4 computes the AWS Signature Version 4 signature for canonical request
// pieces. It is stdlib-only (crypto/hmac, crypto/sha256) and matches the
// official aws-sig-v4-test-suite vectors.
func signV4(opts sigV4Options) string {
	canonicalRequest := strings.Join([]string{
		opts.method,
		opts.canonicalURI,
		"", // POST form requests carry no canonical query string
		opts.canonicalHeaders,
		opts.signedHeaders,
		opts.payloadHash,
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		opts.amzDate,
		opts.scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	parts := strings.Split(opts.scope, "/")
	if len(parts) != 4 {
		return ""
	}
	signingKey := hmacSHA256([]byte("AWS4"+opts.secretKey), parts[0])
	signingKey = hmacSHA256(signingKey, parts[1])
	signingKey = hmacSHA256(signingKey, parts[2])
	signingKey = hmacSHA256(signingKey, "aws4_request")
	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

func (a *AWSAdapter) redact(value string) error {
	return errors.New(a.redactString(value))
}

func (a *AWSAdapter) redactString(value string) string {
	a.mu.Lock()
	secrets := []string{a.secretKey, a.sessionToken, a.oneTimeSecret}
	a.mu.Unlock()
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func tagValue(tags map[string]string, key, fallback string) string {
	if value := strings.TrimSpace(tags[key]); value != "" {
		return value
	}
	return fallback
}

func tagInt(tags map[string]string, key string, fallback int) int {
	value := strings.TrimSpace(tags[key])
	if value == "" {
		return fallback
	}
	days := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return fallback
		}
		days = days*10 + int(char-'0')
	}
	if days < 1 || days > 3650 {
		return fallback
	}
	return days
}

func tagList(tags map[string]string, key string) []string {
	value := strings.TrimSpace(tags[key])
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	contacts := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			contacts = append(contacts, trimmed)
		}
	}
	return contacts
}
