package lifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

type memoryRepository struct {
	mu       sync.Mutex
	snapshot Snapshot
	hasState bool
	changes  []chan struct{}
	closed   bool
}

func (r *memoryRepository) Load(context.Context) (Snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.hasState {
		return Snapshot{}, ErrNoSnapshot
	}
	return r.snapshot, nil
}

func (r *memoryRepository) Save(_ context.Context, snapshot Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot = snapshot
	r.hasState = true
	for _, ch := range r.changes {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return nil
}

func (r *memoryRepository) Changes(ctx context.Context) (<-chan struct{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := make(chan struct{}, 1)
	r.changes = append(r.changes, ch)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (r *memoryRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func TestPersistentStoreRestoresSnapshotAndDoesNotRediscover(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	repository := &memoryRepository{}
	first, err := NewPersistentStore(context.Background(), now(), adapter, repository)
	if err != nil {
		t.Fatalf("first NewPersistentStore() error = %v", err)
	}
	if len(first.List()) != 1 {
		t.Fatalf("first list length = %d, want 1", len(first.List()))
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}

	adapter.discoveries = nil
	second, err := NewPersistentStore(context.Background(), now().Add(24*time.Hour), adapter, repository)
	if err != nil {
		t.Fatalf("second NewPersistentStore() error = %v", err)
	}
	defer second.Close()
	identities := second.List()
	if len(identities) != 1 || identities[0].ID != "payments-api" {
		t.Fatalf("restored identities = %+v, want payments-api", identities)
	}
}

func TestPersistentStorePersistsMutationsBeforeReturning(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	repository := &memoryRepository{}
	store, err := NewPersistentStore(context.Background(), now(), adapter, repository)
	if err != nil {
		t.Fatalf("NewPersistentStore() error = %v", err)
	}
	defer store.Close()
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "payments-api"}, now()); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	loaded, err := repository.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(loaded.Runs) != 1 || loaded.Runs[0].Status != protocol.RotationSucceeded {
		t.Fatalf("persisted runs = %+v, want one succeeded run", loaded.Runs)
	}
}
