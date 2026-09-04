package main

import (
	"reflect"
	"testing"

	"github.com/mutandae/mutandae/internal/provider"
)

func TestConfiguredScopeParsesEnvironmentAllowAndDenyPatterns(t *testing.T) {
	const variable = "MUTANDAE_TEST_SCOPE"
	t.Setenv(variable, "mutandae-demo-*, worker-?, !mutandae-demo-secret")

	scope, err := configuredScope(variable)
	if err != nil {
		t.Fatalf("configuredScope() error = %v", err)
	}
	want := provider.Scope{
		Allow: []string{"mutandae-demo-*", "worker-?"},
		Deny:  []string{"mutandae-demo-secret"},
	}
	if !reflect.DeepEqual(scope, want) {
		t.Fatalf("configuredScope() = %+v, want %+v", scope, want)
	}
	if scope.Match("mutandae-demo-orders") == false || scope.Match("mutandae-demo-secret") {
		t.Fatal("configured allow/deny patterns did not govern matches")
	}
}

func TestConfiguredScopeDefaultsToDemoScopeWhenUnset(t *testing.T) {
	const variable = "MUTANDAE_TEST_SCOPE_DEFAULT"
	t.Setenv(variable, "")

	scope, err := configuredScope(variable)
	if err != nil {
		t.Fatalf("configuredScope() error = %v", err)
	}
	if !reflect.DeepEqual(scope, provider.DemoScope()) {
		t.Fatalf("configuredScope() = %+v, want demo scope %+v", scope, provider.DemoScope())
	}
}

func TestConfiguredScopeRejectsInvalidPatterns(t *testing.T) {
	const variable = "MUTANDAE_TEST_SCOPE_INVALID"
	t.Setenv(variable, "mutandae-demo-[")

	if _, err := configuredScope(variable); err == nil {
		t.Fatal("configuredScope accepted an invalid path.Match pattern")
	}
}
