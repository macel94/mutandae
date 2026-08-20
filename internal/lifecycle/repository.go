package lifecycle

import (
	"context"
	"errors"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// ErrNoSnapshot means a repository has not been initialized for this demo
// environment yet. The control plane responds by discovering the provider seed.
var ErrNoSnapshot = errors.New("lifecycle snapshot does not exist")

// ErrPersistenceFailure means a lifecycle change could not be durably written.
var ErrPersistenceFailure = errors.New("lifecycle persistence failed")

// Snapshot is the serializable control-plane state persisted by a Repository.
// It contains protocol objects only; credential secret material is never part
// of the snapshot.
type Snapshot struct {
	Identities []protocol.MachineIdentity `json:"identities"`
	Events     []protocol.LifecycleEvent  `json:"events"`
	Runs       []protocol.RotationRun     `json:"runs"`
	NextEvent  int                        `json:"next_event"`
	NextRun    int                        `json:"next_run"`
}

// Repository is the lifecycle persistence and fan-out boundary. Save must make
// a snapshot visible before returning. Changes emits notifications after a
// writer publishes a new snapshot; consumers reload the snapshot rather than
// trusting the notification payload.
type Repository interface {
	Load(ctx context.Context) (Snapshot, error)
	Save(ctx context.Context, snapshot Snapshot) error
	Changes(ctx context.Context) (<-chan struct{}, error)
	Close() error
}
