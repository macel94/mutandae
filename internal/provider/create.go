package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// CloudCreate is the provisioning capability of a CloudAdapter. It provisions a
// brand-new, zero-permission machine identity in the provider's tenant: no
// policy is attached, no role is bound, and no login path is created. The
// credential used by the adapter must itself be least-privilege so a
// misbehaving caller cannot escalate.
//
// Create returns a protocol.ProvisionResponse whose OneTimeSecret is written
// only to the single HTTP response and is never persisted by the control plane.
type CloudCreate interface {
	Create(ctx context.Context, name string) (protocol.ProvisionResponse, error)
}

// ErrCreateUnsupported is returned when a provider adapter does not implement
// provisioning (for example a simulator). The web layer maps it to a 409
// conflict so demo users know real tenants are required for this action.
var ErrCreateUnsupported = &createUnsupportedError{}

type createUnsupportedError struct{}

func (*createUnsupportedError) Error() string {
	return "provisioning is not supported by this provider adapter"
}

// demoPrefix reserves the identity namespace that the public demo may create
// identities in. The least-privilege server credentials on every cloud are
// scoped exclusively to this prefix, so no visitor can ever touch a
// non-demo identity, and the identities created here are always zero-permission.
const demoPrefix = "mutandae-demo-"

func isDemoName(name string) bool {
	return strings.HasPrefix(name, demoPrefix)
}

// buildDemoName composes a unique, prefixed identity name safe for all three
// providers. Appending randomness guarantees uniqueness even when a previous
// demo identity with the same hint was retired and deleted.
func buildDemoName(hint string, suffixHex int) (string, error) {
	hint = strings.ToLower(strings.TrimSpace(hint))
	if hint != "" {
		for _, r := range hint {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", errors.New("demo identity hint may only contain a-z, 0-9 and '-'")
			}
		}
		if len(hint) > 20 {
			hint = hint[:20]
		}
	}
	raw := make([]byte, (suffixHex+1)/2)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	suffix := hex.EncodeToString(raw)[:suffixHex]
	name := demoPrefix
	if hint != "" {
		name = demoPrefix + hint + "-"
	}
	name += suffix
	return name, nil
}
