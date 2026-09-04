package config

import "testing"

func TestValidateAuthMode(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment string
		mode        string
		wantError   bool
	}{
		{name: "default preview", environment: "preview", mode: "", wantError: false},
		{name: "oidc live", environment: "live", mode: "oidc", wantError: false},
		{name: "token live", environment: "LIVE", mode: "token", wantError: false},
		{name: "none preview", environment: "preview", mode: "none", wantError: false},
		{name: "none live fails closed", environment: "live", mode: "none", wantError: true},
		{name: "unknown mode", environment: "preview", mode: "password", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateAuthMode(test.environment, test.mode); (err != nil) != test.wantError {
				t.Fatalf("ValidateAuthMode(%q, %q) error = %v, wantError=%t", test.environment, test.mode, err, test.wantError)
			}
		})
	}
}
