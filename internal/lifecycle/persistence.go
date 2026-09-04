package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func (s *Store) snapshotLocked() Snapshot {
	identities := make([]protocol.MachineIdentity, 0, len(s.identities))
	for _, identity := range s.identities {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })

	events := make([]protocol.LifecycleEvent, 0)
	for _, identityEvents := range s.events {
		events = append(events, identityEvents...)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })

	runs := make([]protocol.RotationRun, 0)
	for _, identityRuns := range s.runs {
		runs = append(runs, identityRuns...)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ID < runs[j].ID })

	return Snapshot{Identities: identities, Events: events, Runs: runs, NextEvent: s.nextEvent, NextRun: s.nextRun}
}

func (s *Store) restoreLocked(snapshot Snapshot) {
	s.identities = make(map[string]protocol.MachineIdentity, len(snapshot.Identities))
	s.events = make(map[string][]protocol.LifecycleEvent)
	s.runs = make(map[string][]protocol.RotationRun)
	for _, identity := range snapshot.Identities {
		s.identities[identity.ID] = identity
	}
	for _, event := range snapshot.Events {
		s.events[event.IdentityID] = append(s.events[event.IdentityID], event)
	}
	for _, run := range snapshot.Runs {
		s.runs[run.IdentityID] = append(s.runs[run.IdentityID], run)
	}
	s.nextEvent = snapshot.NextEvent
	s.nextRun = snapshot.NextRun
}

func (s *Store) persistLocked(ctx context.Context) error {
	if s.repository == nil {
		return nil
	}
	if err := s.repository.Save(ctx, s.snapshotLocked()); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistenceFailure, err)
	}
	return nil
}

func (s *Store) startWatcher() error {
	if s.repository == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	changes, err := s.repository.Changes(ctx)
	if err != nil {
		cancel()
		return err
	}
	s.watchCancel = cancel
	s.watchDone = make(chan struct{})
	go func() {
		defer close(s.watchDone)
		for range changes {
			snapshot, err := s.repository.Load(ctx)
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.restoreLocked(snapshot)
			s.mu.Unlock()
		}
	}()
	return nil
}

// Close stops the Redis watcher and closes the persistence repository. It is
// safe to call for the in-memory store too.
func (s *Store) Close() error {
	if s.watchCancel != nil {
		s.watchCancel()
		if s.watchDone != nil {
			<-s.watchDone
		}
	}
	var errs []error
	if s.auditSink != nil {
		if err := s.auditSink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.repository != nil {
		if err := s.repository.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
