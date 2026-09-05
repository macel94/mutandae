package config

import (
	"strings"
	"testing"
)

func TestValidateAuthMode(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment string
		mode        string
		wantError   bool
		wantWarning bool
	}{
		{name: "default preview", environment: "preview", mode: "", wantError: false, wantWarning: false},
		{name: "oidc live", environment: "live", mode: "oidc", wantError: false, wantWarning: false},
		{name: "token live", environment: "LIVE", mode: "token", wantError: false, wantWarning: false},
		{name: "none preview", environment: "preview", mode: "none", wantError: false, wantWarning: false},
		{name: "none live warns loudly, does not fail", environment: "live", mode: "none", wantError: false, wantWarning: true},
		{name: "unknown mode", environment: "preview", mode: "password", wantError: true, wantWarning: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			warnings, err := ValidateAuthMode(test.environment, test.mode)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateAuthMode(%q, %q) error = %v, wantError=%t", test.environment, test.mode, err, test.wantError)
			}
			hasWarning := len(warnings) > 0
			if hasWarning != test.wantWarning {
				t.Fatalf("ValidateAuthMode(%q, %q) warnings = %v, wantWarning=%t", test.environment, test.mode, warnings, test.wantWarning)
			}
			if test.wantWarning && !strings.Contains(strings.Join(warnings, " "), "unauthenticated") {
				t.Fatalf("live+none warning must state that the deployment accepts unauthenticated traffic; got %v", warnings)
			}
		})
	}
}
