package protocol

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

//go:embed schema/mutandae.v1.json
var protocolSchema []byte

type schemaDocument struct {
	ID   string                      `json:"$id"`
	Defs map[string]schemaDefinition `json:"$defs"`
}

type schemaDefinition struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
	Enum       []string                   `json:"enum"`
}

func loadProtocolSchema(t *testing.T) schemaDocument {
	t.Helper()
	var document schemaDocument
	if err := json.Unmarshal(protocolSchema, &document); err != nil {
		t.Fatalf("parse protocol schema: %v", err)
	}
	if document.ID == "" || len(document.Defs) == 0 {
		t.Fatal("protocol schema has no id or definitions")
	}
	return document
}

func TestProtocolSchemaEnumsStayInSync(t *testing.T) {
	document := loadProtocolSchema(t)
	enums := map[string][]string{
		"State":          {string(StateRegistered), string(StateActive), string(StateRenewing), string(StateRetired)},
		"Health":         {string(HealthHealthy), string(HealthAttention)},
		"Urgency":        {string(UrgencyHealthy), string(UrgencyExpiring), string(UrgencyOverdue), string(UrgencyRetired)},
		"RotationStatus": {string(RotationPending), string(RotationRunning), string(RotationSucceeded), string(RotationFailed), string(RotationRollBack)},
		"Outcome":        {string(OutcomeSuccess), string(OutcomeInProgress), string(OutcomeAttention), string(OutcomeFailure), string(OutcomeCancelled)},
		"ErrorCode":      {string(ErrCodeInvalidRequest), string(ErrCodeForbidden), string(ErrCodeConformanceFailure), string(ErrCodeNotFound), string(ErrCodeInvalidTransition), string(ErrCodeAlreadyRetired), string(ErrCodeRotationInProgress), string(ErrCodeProviderFailure), string(ErrCodeUnsupportedVersion), string(ErrCodeConflict), string(ErrCodeInternal), string(ErrCodeUnimplemented)},
		"EventType": {
			string(EventIdentityDiscovered), string(EventIdentityRegistered), string(EventIdentityImported),
			string(EventOwnershipAssigned), string(EventOwnershipChanged), string(EventPolicyApplied),
			string(EventRenewalAlerted), string(EventExpiryImminent), string(EventExpiryOverdue),
			string(EventRotationRequested), string(EventRotationStarted), string(EventRotationCompleted),
			string(EventRotationFailed), string(EventRotationRollBack), string(EventCredentialDelivered),
			string(EventCredentialUsed), string(EventCredentialRevoked), string(EventIntegrationConnected),
			string(EventApplicationCreated), string(EventSecretCreated), string(EventSecretRead),
			string(EventSecretInvalidated), string(EventIntegrationClosed), string(EventIdentityRetired),
			string(EventIdentityRevoked), string(EventIdentityResurrected), string(EventIdentityDeleted),
		},
	}
	for definitionName, values := range enums {
		definition, ok := document.Defs[definitionName]
		if !ok {
			t.Errorf("schema is missing enum definition %q", definitionName)
			continue
		}
		for _, value := range values {
			if !containsString(definition.Enum, value) {
				t.Errorf("schema enum %s is missing protocol constant %q", definitionName, value)
			}
		}
	}
}

func TestProtocolSchemaTaggedTypesStayInSync(t *testing.T) {
	document := loadProtocolSchema(t)
	types := []struct {
		name     string
		value    any
		required []string
	}{
		{"MachineIdentity", MachineIdentity{}, []string{"id", "name", "provider", "ownership", "state", "health"}},
		{"RotateRequest", RotateRequest{}, []string{"id"}},
		{"RetireRequest", RetireRequest{}, []string{"id", "confirm"}},
		{"LifecycleEvent", LifecycleEvent{}, []string{"id", "identity_id", "type", "summary", "actor", "outcome", "at"}},
		{"RotationRun", RotationRun{}, []string{"id", "identity_id", "status"}},
		{"CredentialReference", CredentialReference{}, []string{"kind", "location"}},
	}
	for _, testCase := range types {
		t.Run(testCase.name, func(t *testing.T) {
			definition, ok := document.Defs[testCase.name]
			if !ok {
				t.Fatalf("schema is missing definition")
			}
			for _, field := range jsonFieldNames(reflect.TypeOf(testCase.value)) {
				if _, ok := definition.Properties[field]; !ok {
					t.Errorf("schema %s is missing JSON property %q", testCase.name, field)
				}
			}
			for _, field := range testCase.required {
				if !containsString(definition.Required, field) {
					t.Errorf("schema %s is missing required property %q", testCase.name, field)
				}
			}
		})
	}
}

func TestProtocolSchemaVersionIdentity(t *testing.T) {
	document := loadProtocolSchema(t)
	if !strings.Contains(document.ID, APIVersion) {
		t.Fatalf("schema $id %q does not identify protocol %s", document.ID, APIVersion)
	}
	found := 0
	for name, definition := range document.Defs {
		property, ok := definition.Properties["api_version"]
		if !ok {
			continue
		}
		var value struct {
			Const string `json:"const"`
		}
		if err := json.Unmarshal(property, &value); err != nil {
			t.Fatalf("parse %s.api_version: %v", name, err)
		}
		found++
		if value.Const != APIVersion {
			t.Errorf("schema %s.api_version const = %q, want %q", name, value.Const, APIVersion)
		}
	}
	if found == 0 {
		t.Fatal("schema contains no api_version identity")
	}
}

func jsonFieldNames(value reflect.Type) []string {
	fields := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.PkgPath != "" { // unexported
			continue
		}
		tag := field.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, name)
	}
	return fields
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
