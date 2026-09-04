package provider

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// DemoScopePattern is the safe namespace used by the public simulator and
// demo wiring. Scope patterns use path.Match's fnmatch-style syntax, not
// regular expressions: *, ?, and [...] are supported.
const DemoScopePattern = "mutandae-demo-*"

// Scope is the provider identity namespace a Mutandae adapter may govern.
// Allow patterns are inclusive; an empty Allow list means allow all when Scope
// is evaluated directly. Adapter constructors apply their own safe defaults:
// simulators use DemoScopePattern and real adapters require a non-empty Allow
// list. Deny always wins over Allow.
type Scope struct {
	Allow []string
	Deny  []string
}

// Match reports whether name is in this scope. Patterns are fnmatch-style
// path.Match patterns, not regular expressions. Invalid patterns never match;
// constructors and ParseScope reject them before an adapter is wired.
func (s Scope) Match(name string) bool {
	for _, pattern := range s.Deny {
		if scopePatternMatch(pattern, name) {
			return false
		}
	}
	if len(s.Allow) == 0 {
		return true
	}
	for _, pattern := range s.Allow {
		if scopePatternMatch(pattern, name) {
			return true
		}
	}
	return false
}

// Validate checks all configured fnmatch-style patterns.
func (s Scope) Validate() error {
	for _, pattern := range append(append([]string(nil), s.Allow...), s.Deny...) {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return fmt.Errorf("provider scope pattern is empty")
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("provider scope pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// ParseScope parses a comma-separated allow-list. A leading ! marks a deny
// pattern, which makes environment values useful for both lists while keeping
// the documented common form (a comma-separated list of allow patterns).
func ParseScope(value string) (Scope, error) {
	var scope Scope
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "!") {
			item = strings.TrimSpace(strings.TrimPrefix(item, "!"))
			if item == "" {
				return Scope{}, fmt.Errorf("provider scope deny pattern is empty")
			}
			scope.Deny = append(scope.Deny, item)
			continue
		}
		scope.Allow = append(scope.Allow, item)
	}
	if len(scope.Allow) == 0 && len(scope.Deny) == 0 {
		return Scope{}, fmt.Errorf("provider scope must contain at least one pattern")
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

// DemoScope returns a copy of the safe public-demo scope.
func DemoScope() Scope { return Scope{Allow: []string{DemoScopePattern}} }

func scopePatternMatch(pattern, name string) bool {
	matched, err := path.Match(strings.TrimSpace(pattern), name)
	return err == nil && matched
}

func forbiddenScopeError(kind, name string, scope Scope) error {
	patterns := strings.Join(scope.Allow, ", ")
	if patterns == "" {
		patterns = "<none>"
	}
	return fmt.Errorf("%w: %s identity %q is outside the configured provider scope (allow: %s)", protocol.ErrForbidden, kind, name, patterns)
}

func validateRealScope(scope Scope, legacyDemoOnly bool) (Scope, error) {
	if legacyDemoOnly && len(scope.Allow) == 0 {
		scope.Allow = []string{DemoScopePattern}
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, err
	}
	if len(scope.Allow) == 0 {
		if len(scope.Deny) > 0 {
			return Scope{}, fmt.Errorf("real provider adapter requires a non-empty scope allow list")
		}
		// A zero Scope is accepted as a legacy compatibility value for direct
		// in-process fixtures. The composition root always parses an explicit
		// scope (DemoScope when the environment is unset), so a running
		// preview/live adapter never receives this compatibility value.
		scope = Scope{Allow: []string{"*"}}
	}
	return scope, nil
}

func simulatorScope(scope Scope) (Scope, error) {
	if len(scope.Allow) == 0 && len(scope.Deny) == 0 {
		scope = DemoScope()
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

func isDemoScope(scope Scope) bool {
	for _, pattern := range scope.Allow {
		if strings.TrimSpace(pattern) == DemoScopePattern {
			return true
		}
	}
	return false
}

// simulatorConstructorScope keeps the historical no-argument constructors
// useful to package-local fixtures while making an explicitly zero Scope safe.
// Composition-root wiring always supplies a parsed scope, so invalid patterns
// cannot reach a running adapter.
func simulatorConstructorScope(scopes []Scope) Scope {
	if len(scopes) == 0 {
		return Scope{Allow: []string{"*"}}
	}
	if len(scopes[0].Allow) == 0 && len(scopes[0].Deny) == 0 {
		return DemoScope()
	}
	return scopes[0]
}

// buildScopedName generates a provider-safe identity name under the first
// allow pattern. It preserves the public demo namespace for the usual
// mutandae-demo-* pattern and also makes simple custom prefixes usable for
// provisioning. Complex patterns are validated by retrying candidates until
// one matches; a bounded failure is returned rather than weakening the scope.
func buildScopedName(scope Scope, hint string, suffixHex int) (string, error) {
	if len(scope.Allow) == 0 {
		return "", fmt.Errorf("provider scope has no allow pattern for provisioning")
	}
	pattern := strings.TrimSpace(scope.Allow[0])
	prefix := pattern
	for index, char := range pattern {
		if char == '*' || char == '?' || char == '[' {
			prefix = pattern[:index]
			break
		}
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = demoPrefix
	}
	if strings.HasSuffix(prefix, "*") {
		prefix = strings.TrimSuffix(prefix, "*")
	}
	baseHint := strings.ToLower(strings.TrimSpace(hint))
	if baseHint != "" {
		for _, char := range baseHint {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
				return "", fmt.Errorf("identity hint may only contain a-z, 0-9 and '-'")
			}
		}
		if len(baseHint) > 20 {
			baseHint = baseHint[:20]
		}
	}
	for attempt := 0; attempt < 8; attempt++ {
		raw := make([]byte, (suffixHex+1)/2)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		candidate := prefix
		if baseHint != "" {
			candidate += baseHint + "-"
		}
		candidate += hex.EncodeToString(raw)[:suffixHex]
		if scope.Match(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not generate an identity inside provider scope pattern %q", pattern)
}

// planned constructs a validated-looking operation while keeping provider
// request and response shapes out of the protocol package. The provider kind
// is part of the short token only; identity and detail remain provider-neutral.
func planned(op, identity, detail string, reversible, destructive bool) protocol.PlannedOperation {
	return protocol.PlannedOperation{
		Op:          op,
		Identity:    identity,
		Detail:      detail,
		Reversible:  reversible,
		Destructive: destructive,
	}
}
