package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// fakeIAM is an in-memory IAM Query API server that enforces the two-key
// ceiling and records request signatures so tests can assert correct SigV4
// signing and secret hygiene.
type fakeIAM struct {
	t          *testing.T
	mu         sync.Mutex
	users      map[string][]fakeIAMKey
	profiles   map[string]bool
	breakNext  bool
	echoSecret string
}

type fakeIAMKey struct {
	AccessKeyID string
	Secret      string
	Status      string
	CreateDate  time.Time
}

func newFakeIAM(t *testing.T) *fakeIAM {
	return &fakeIAM{
		t:        t,
		users:    map[string][]fakeIAMKey{},
		profiles: map[string]bool{},
	}
}

const (
	fakeAWSAccount    = "123456789012"
	fakeAccessKeyID   = "AKIATESTKEYID"
	fakeUserARN       = "arn:aws:iam::123456789012:user/"
	fakeSigningSecret = "the-very-secret-aws-secret"
)

func (f *fakeIAM) seed(user string, created time.Time, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[user] = []fakeIAMKey{{
		AccessKeyID: fakeAccessKeyID + strings.ToUpper(user[0:1]),
		Secret:      secret,
		Status:      "Active",
		CreateDate:  created,
	}}
	f.profiles[user] = true
}

// userTags are the MUTANDAE_* tags every seeded test user carries; they are
// returned from GetUser (and the test ListUsers XML) so the adapter can map
// ownership metadata.
var userTags = []iamTag{
	{Key: "MUTANDAE_TEAM", Value: "Platform Engineering"},
	{Key: "MUTANDAE_SERVICE", Value: "CI deployment"},
	{Key: "MUTANDAE_PURPOSE", Value: "Deploys the control plane"},
	{Key: "MUTANDAE_CRITICALITY", Value: "high"},
	{Key: "MUTANDAE_ENVIRONMENT", Value: "production"},
	{Key: "MUTANDAE_RENEWAL_DAYS", Value: "60"},
	{Key: "MUTANDAE_CONTACTS", Value: "iam-owner@example.com,oncall@example.com"},
}

func (f *fakeIAM) listUsersXML() string {
	var members strings.Builder
	for user := range f.users {
		members.WriteString(`
      <member>
        <Path>/</Path>
        <UserName>` + user + `</UserName>
        <UserId>AIDAEXAMPLE123</UserId>
        <Arn>` + fakeUserARN + user + `</Arn>
        <CreateDate>2026-06-01T00:00:00Z</CreateDate>
        <Tags>` + tagsXML(userTags) + `</Tags>
      </member>`)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult>
    <Users>` + members.String() + `
    </Users>
    <IsTruncated>false</IsTruncated>
  </ListUsersResult>
  <ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata>
</ListUsersResponse>`
}

func (f *fakeIAM) getUser(w http.ResponseWriter, userName string) {
	if _, ok := f.users[userName]; !ok {
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>The user with name `+userName+` cannot be found.</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`)
		return
	}
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetUserResult>
    <User>
      <Path>/</Path>
      <UserName>%s</UserName>
      <UserId>AIDAEXAMPLE123</UserId>
      <Arn>%s%s</Arn>
      <CreateDate>2026-06-01T00:00:00Z</CreateDate>
      <Tags>%s</Tags>
    </User>
  </GetUserResult>
  <ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata>
</GetUserResponse>`, userName, fakeUserARN, userName, tagsXML(userTags))
}

func tagsXML(tags []iamTag) string {
	var members strings.Builder
	for _, tag := range tags {
		members.WriteString(`<member><Key>` + tag.Key + `</Key><Value>` + tag.Value + `</Value></member>`)
	}
	return members.String()
}

func (f *fakeIAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("fake IAM: parse form: %v", err)
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("Action")

	auth := r.Header.Get("Authorization")
	if !regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIATESTKEYID/[0-9]{8}/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$`).MatchString(auth) {
		f.t.Errorf("fake IAM: malformed Authorization header %q", auth)
	}
	if r.Header.Get("X-Amz-Date") == "" {
		f.t.Errorf("fake IAM: missing X-Amz-Date")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.breakNext {
		f.breakNext = false
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InternalError</Code><Message>debug payload %s</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`, f.echoSecret)
		return
	}
	switch action {
	case "ListUsers":
		fmt.Fprint(w, f.listUsersXML())
	case "GetUser":
		f.getUser(w, r.FormValue("UserName"))
	case "ListAccessKeys":
		fmt.Fprint(w, f.listAccessKeysXML(r.FormValue("UserName")))
	case "CreateAccessKey":
		f.createAccessKey(w, r.FormValue("UserName"))
	case "DeleteAccessKey":
		f.deleteAccessKey(w, r.FormValue("UserName"), r.FormValue("AccessKeyId"))
	case "DeleteLoginProfile":
		f.deleteLoginProfile(w, r.FormValue("UserName"))
	default:
		f.t.Errorf("fake IAM: unexpected action %q", action)
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (f *fakeIAM) listAccessKeysXML(userName string) string {
	keys, ok := f.users[userName]
	if !ok {
		return `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>The user with name ` + userName + ` cannot be found.</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`
	}
	var members strings.Builder
	for _, key := range keys {
		members.WriteString(`
      <member>
        <UserName>` + userName + `</UserName>
        <AccessKeyId>` + key.AccessKeyID + `</AccessKeyId>
        <Status>` + key.Status + `</Status>
        <CreateDate>` + key.CreateDate.UTC().Format(time.RFC3339) + `</CreateDate>
      </member>`)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult>
    <AccessKeyMetadata>` + members.String() + `
    </AccessKeyMetadata>
    <IsTruncated>false</IsTruncated>
  </ListAccessKeysResult>
  <ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata>
</ListAccessKeysResponse>`
}

func (f *fakeIAM) createAccessKey(w http.ResponseWriter, userName string) {
	keys := f.users[userName]
	if len(keys) >= 2 {
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>LimitExceeded</Code><Message>Cannot exceed quota for AccessKeysPerUser: 2</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`)
		return
	}
	key := fakeIAMKey{
		AccessKeyID: fakeAccessKeyID + fmt.Sprintf("%02d", len(keys)+1),
		Secret:      "one-time-secret-" + userName,
		Status:      "Active",
		CreateDate:  time.Now().UTC(),
	}
	f.users[userName] = append(keys, key)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateAccessKeyResult>
    <AccessKey>
      <UserName>%s</UserName>
      <AccessKeyId>%s</AccessKeyId>
      <SecretAccessKey>%s</SecretAccessKey>
      <Status>Active</Status>
      <CreateDate>%s</CreateDate>
    </AccessKey>
  </CreateAccessKeyResult>
  <ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata>
</CreateAccessKeyResponse>`, userName, key.AccessKeyID, key.Secret, key.CreateDate.Format(time.RFC3339))
}

func (f *fakeIAM) deleteAccessKey(w http.ResponseWriter, userName, keyID string) {
	keys := f.users[userName]
	kept := keys[:0]
	deleted := false
	for _, key := range keys {
		if key.AccessKeyID == keyID {
			deleted = true
			continue
		}
		kept = append(kept, key)
	}
	f.users[userName] = kept
	if !deleted {
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>The Access Key with id `+keyID+` cannot be found.</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`)
		return
	}
	fmt.Fprint(w, `<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`)
}

func (f *fakeIAM) deleteLoginProfile(w http.ResponseWriter, userName string) {
	if !f.profiles[userName] {
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>Login Profile for User `+userName+` cannot be found.</Message></Error><RequestId>EXAMPLE</RequestId></ErrorResponse>`)
		return
	}
	delete(f.profiles, userName)
	fmt.Fprint(w, `<DeleteLoginProfileResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>EXAMPLE</RequestId></ResponseMetadata></DeleteLoginProfileResponse>`)
}

func newAWSAdapterForTest(t *testing.T, iam *fakeIAM, fixed time.Time) (*AWSAdapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(iam)
	adapter, err := NewAWSAdapter(AWSAdapterConfig{
		AccountID:   fakeAWSAccount,
		Region:      "us-east-1",
		AccessKeyID: fakeAccessKeyID,
		SecretKey:   fakeSigningSecret,
		Endpoint:    server.URL,
		HTTPClient:  server.Client(),
		Now:         func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("NewAWSAdapter() error = %v", err)
	}
	return adapter, server
}

func assertAWSIdentity(t *testing.T, identity protocol.MachineIdentity) {
	t.Helper()
	identity.ID = identity.Name
	if err := protocol.ValidateIdentity(&identity); err != nil {
		t.Fatalf("identity is non-conformant: %v", err)
	}
	if identity.Provider.Provider != "aws-iam" {
		t.Errorf("provider = %q, want aws-iam", identity.Provider.Provider)
	}
	if identity.Provider.ProviderID != "ci-deployer" {
		t.Errorf("provider_id = %q, want ci-deployer", identity.Provider.ProviderID)
	}
	if identity.Provider.AccountID != fakeAWSAccount {
		t.Errorf("account_id = %q, want %s", identity.Provider.AccountID, fakeAWSAccount)
	}
	if identity.Credential.Kind != "access_key" {
		t.Errorf("credential.kind = %q, want access_key", identity.Credential.Kind)
	}
	if !strings.HasPrefix(identity.Credential.Fingerprint, "sha256:") {
		t.Errorf("credential.fingerprint = %q, want sha256: prefix", identity.Credential.Fingerprint)
	}
}

func TestAWSAdapterDiscoversConformantIdentities(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("ci-deployer", fixed.Add(-40*24*time.Hour), "seed-secret")
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()

	identities, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("Discover() returned %d identities, want 1", len(identities))
	}
	identity := identities[0]
	assertAWSIdentity(t, identity)
	if identity.Ownership.Team != "Platform Engineering" {
		t.Errorf("ownership.team = %q, want tag value", identity.Ownership.Team)
	}
	if identity.Policy.RenewalPeriod != "P60D" {
		t.Errorf("renewal_period = %q, want P60D from tag", identity.Policy.RenewalPeriod)
	}
	if len(identity.Ownership.Contacts) != 2 {
		t.Errorf("contacts = %v, want 2 tagged contacts", identity.Ownership.Contacts)
	}
	if strings.Contains(fmt.Sprintf("%+v", identity), fakeSigningSecret) {
		t.Fatal("adapter leaked the signing secret into a protocol identity")
	}
}

func TestAWSAdapterRotateRespectsTwoKeyCeiling(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("ci-deployer", fixed.Add(-40*24*time.Hour), "seed-secret")
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()

	discovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	identity := discovered[0]
	identity.ID = identity.Name

	rotated, err := adapter.Rotate(context.Background(), identity)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if rotated.Credential.KeyID == identity.Credential.KeyID {
		t.Fatalf("rotate did not replace the access key id")
	}
	if rotated.Credential.Fingerprint == identity.Credential.Fingerprint {
		t.Fatalf("rotate did not replace the credential fingerprint")
	}
	oneTime := adapter.ConsumeOneTimeSecret()
	if oneTime == "" {
		t.Fatal("rotation produced no one-time secret")
	}
	if adapter.ConsumeOneTimeSecret() != "" {
		t.Fatal("one-time secret was not cleared after consumption")
	}
	if rotated.Credential.KeyID == identity.Credential.KeyID {
		t.Fatalf("unexpected rotated key id %q", rotated.Credential.KeyID)
	}
	keys := iam.users["ci-deployer"]
	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 key after rotation, got %d", len(keys))
	}
	if keys[0].AccessKeyID != rotated.Credential.KeyID {
		t.Fatalf("active key %q does not match rotated evidence %q", keys[0].AccessKeyID, rotated.Credential.KeyID)
	}
}

func TestAWSAdapterRotateWithTwoKeysPrefersCurrent(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("ci-deployer", fixed.Add(-60*24*time.Hour), "seed-secret")
	// Add a second, newer key directly (simulates a previous 2-key rotation).
	iam.mu.Lock()
	iam.users["ci-deployer"] = append(iam.users["ci-deployer"], fakeIAMKey{
		AccessKeyID: fakeAccessKeyID + "99",
		Secret:      "previous-secret",
		Status:      "Active",
		CreateDate:  fixed.Add(-30 * 24 * time.Hour),
	})
	iam.mu.Unlock()

	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()
	discovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	identity := discovered[0]
	identity.ID = identity.Name
	if identity.Credential.KeyID != fakeAccessKeyID+"99" {
		t.Fatalf("discovered credential = %q, want newest key", identity.Credential.KeyID)
	}

	rotated, err := adapter.Rotate(context.Background(), identity)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	keys := iam.users["ci-deployer"]
	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 key after ceiling rotation, got %d: %+v", len(keys), keys)
	}
	if rotated.Credential.KeyID != keys[0].AccessKeyID {
		t.Fatalf("rotated evidence %q does not match provider state %q", rotated.Credential.KeyID, keys[0].AccessKeyID)
	}
}

func TestAWSAdapterRetireDeletesKeysAndLoginProfile(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("ci-deployer", fixed.Add(-40*24*time.Hour), "seed-secret")
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()

	identity, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	retired, err := adapter.Retire(context.Background(), identity[0])
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if retired.State != protocol.StateRetired {
		t.Fatalf("retired view state = %q, want retired", retired.State)
	}
	if len(iam.users["ci-deployer"]) != 0 {
		t.Fatalf("provider still holds %d access keys after retire", len(iam.users["ci-deployer"]))
	}
	if iam.profiles["ci-deployer"] {
		t.Fatal("login profile was not deleted during retire")
	}
	rediscovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() after retire error = %v", err)
	}
	if len(rediscovered) != 0 {
		t.Fatalf("retired identity was rediscovered: %+v", rediscovered)
	}
}

func TestAWSAdapterRedactsSecretsFromErrors(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("ci-deployer", fixed.Add(-40*24*time.Hour), "seed-secret")
	iam.breakNext = true
	iam.echoSecret = fakeSigningSecret
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()

	_, err := adapter.Discover(context.Background())
	if err == nil {
		t.Fatal("expected discover to fail against the broken server")
	}
	if strings.Contains(err.Error(), fakeSigningSecret) {
		t.Fatalf("adapter leaked the secret in an error: %v", err)
	}
	if !strings.Contains(err.Error(), "redacted") {
		t.Fatalf("error does not carry the redaction marker: %v", err)
	}
}

func TestAWSAdapterConstructorValidation(t *testing.T) {
	if _, err := NewAWSAdapter(AWSAdapterConfig{SecretKey: "secret", AccessKeyID: "AKIAX"}); err == nil {
		t.Fatal("constructor accepted a missing account id")
	}
	if _, err := NewAWSAdapter(AWSAdapterConfig{AccountID: "123456789012", SecretKey: "secret"}); err == nil {
		t.Fatal("constructor accepted a missing access key id")
	}
	adapter, err := NewAWSAdapter(AWSAdapterConfig{AccountID: "123456789012", AccessKeyID: "AKIAX", SecretKey: fakeSigningSecret})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	defer adapter.Close()
	if adapter.region != "us-east-1" || adapter.endpoint != "https://iam.amazonaws.com" {
		t.Fatalf("defaults not applied: region=%q endpoint=%q", adapter.region, adapter.endpoint)
	}
	if adapter.redactString("prefix "+fakeSigningSecret+" suffix") != "prefix [redacted] suffix" {
		t.Fatal("redaction did not mask the signing secret")
	}
	adapter.Close()
	if adapter.redactString("prefix "+fakeSigningSecret+" suffix") != "prefix "+fakeSigningSecret+" suffix" {
		t.Fatal("Close() did not scrub the signing secret from the adapter")
	}
}

// TestSignV4OfficialVector pins the SigV4 implementation to the official AWS
// Signature Version 4 test-suite "get-vanilla" vector. Without this, the fake
// IAM server only confirms the Authorization header format and real-signed
// requests could be rejected (SignAtureDoesNotMatch) in live clouds.
func TestSignV4OfficialVector(t *testing.T) {
	// From the official aws-sig-v4-test-suite (get-vanilla).
	const (
		secret       = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		amzDate      = "20150830T123600Z"
		dateStamp    = "20150830"
		region       = "us-east-1"
		endpointHost = "example.amazonaws.com"
	)
	canonicalHeaders := "host:" + endpointHost + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	scope := dateStamp + "/" + region + "/service/aws4_request"
	signature := signV4(sigV4Options{
		method:           "GET",
		canonicalURI:     "/",
		canonicalHeaders: canonicalHeaders,
		signedHeaders:    signedHeaders,
		payloadHash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		amzDate:          amzDate,
		scope:            scope,
		secretKey:        secret,
	})
	// Expected signature from the official suite (get-vanilla.authz).
	const want = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if signature != want {
		t.Fatalf("signV4(get-vanilla) = %q, want %q", signature, want)
	}
}

// TestAWSRetireIsIdempotentWhenUserAlreadyGone proves retirement completes
// when the IAM user was already deleted out-of-band (NoSuchEntity), matching
// the demo's honest lifecycle: the governance state converges on retired.
func TestAWSRetireIsIdempotentWhenUserAlreadyGone(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()

	identity := protocol.MachineIdentity{
		Name: "mutandae-demo-gone",
		Provider: protocol.ProviderBinding{
			Provider: "aws-iam", ProviderID: "mutandae-demo-gone", AccountID: "572030963802", Region: "us-east-1",
		},
		Credential: protocol.CredentialReference{Kind: "access_key", KeyID: "AKIGONE"},
		State:      protocol.StateActive,
	}
	// The user does not exist in the fake (never seeded): Retire must succeed.
	view, err := adapter.Retire(context.Background(), identity)
	if err != nil {
		t.Fatalf("Retire of an already-deleted user: %v", err)
	}
	if view.State != protocol.StateRetired {
		t.Fatalf("state = %q, want retired", view.State)
	}
}
