package lifecycle

import (
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// DashboardExpiryWindow is the shared renewal-health horizon used by the
// dashboard and the scheduled worker. ExpiresAt is governance-authoritative
// and is itself derived from Policy.RenewalPeriod when the identity is
// registered or rotated.
const DashboardExpiryWindow = 30 * 24 * time.Hour

// ComputeUrgency derives the same advisory urgency shown by the dashboard:
// retired records are terminal, expired credentials are overdue, credentials
// expiring inside the 30-day dashboard window are expiring, and the rest are
// healthy. The policy period remains the source of ExpiresAt; this helper does
// not invent a second renewal schedule.
func ComputeUrgency(identity protocol.MachineIdentity, now time.Time) protocol.Urgency {
	if identity.State == protocol.StateRetired {
		return protocol.UrgencyRetired
	}
	if !identity.ExpiresAt.After(now) {
		return protocol.UrgencyOverdue
	}
	if identity.ExpiresAt.Before(now.Add(DashboardExpiryWindow)) {
		return protocol.UrgencyExpiring
	}
	return protocol.UrgencyHealthy
}

// RenewalUrgency is an explicit lifecycle-domain alias for callers that want
// to make the renewal-health intent clear at call sites.
func RenewalUrgency(identity protocol.MachineIdentity, now time.Time) protocol.Urgency {
	return ComputeUrgency(identity, now)
}
