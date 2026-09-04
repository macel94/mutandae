package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// Ticker is the injectable clock signal used by Sweeper. The production
// implementation wraps time.Ticker; tests can drive C without sleeping.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type realTicker struct{ ticker *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.ticker.C }
func (t realTicker) Stop()               { t.ticker.Stop() }

// TickerFactory creates one ticker for each wait. Recreating it after each
// sweep lets jitter apply independently to every scheduled interval.
type TickerFactory func(time.Duration) Ticker

// SweeperConfig contains all worker dependencies and scheduling policy.
type SweeperConfig struct {
	Store       *Store
	Clock       func() time.Time
	Interval    time.Duration
	Jitter      time.Duration
	Lease       LeaseManager
	Logger      AuditLogger
	Concurrency int
	NewTicker   TickerFactory
	Random      func() float64
}

// SweepFailure records an identity-specific rotation failure without stopping
// the rest of the renewal sweep.
type SweepFailure struct {
	IdentityID string
	Error      error
}

// SweepResult is the observable outcome of one attempted sweep.
type SweepResult struct {
	Leader     bool
	Considered int
	Rotated    int
	Skipped    int
	Failures   []SweepFailure
}

// Sweeper periodically rotates overdue active identities while one instance
// holds the configured lease. It never mutates retired records.
type Sweeper struct {
	store       *Store
	clock       func() time.Time
	interval    time.Duration
	jitter      time.Duration
	lease       LeaseManager
	logger      AuditLogger
	concurrency int
	newTicker   TickerFactory
	random      func() float64
	limiter     chan struct{}

	attemptMu   sync.Mutex
	lastAttempt map[string]time.Time
	sweepSeq    atomic.Uint64
}

// NewSweeper validates and constructs a scheduled lifecycle worker. A nil
// lease uses the single-process in-memory leader, and a nil logger is a no-op.
func NewSweeper(config SweeperConfig) (*Sweeper, error) {
	if config.Store == nil {
		return nil, errors.New("sweeper store is required")
	}
	if config.Clock == nil {
		return nil, errors.New("sweeper clock is required")
	}
	if config.Interval <= 0 {
		return nil, errors.New("sweeper interval must be positive")
	}
	if config.Jitter < 0 {
		return nil, errors.New("sweeper jitter cannot be negative")
	}
	if config.Jitter > time.Duration(1<<63-1)-config.Interval {
		return nil, errors.New("sweeper interval and jitter exceed the maximum duration")
	}
	if config.Lease == nil {
		config.Lease = NewInMemoryLeaseManager()
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 2
	}
	if config.NewTicker == nil {
		config.NewTicker = func(duration time.Duration) Ticker {
			return realTicker{ticker: time.NewTicker(duration)}
		}
	}
	if config.Random == nil {
		randomSource := rand.New(rand.NewSource(config.Clock().UnixNano()))
		config.Random = randomSource.Float64
	}
	return &Sweeper{
		store:       config.Store,
		clock:       config.Clock,
		interval:    config.Interval,
		jitter:      config.Jitter,
		lease:       config.Lease,
		logger:      config.Logger,
		concurrency: config.Concurrency,
		newTicker:   config.NewTicker,
		random:      config.Random,
		limiter:     make(chan struct{}, config.Concurrency),
		lastAttempt: make(map[string]time.Time),
	}, nil
}

// Sweep performs one lease-protected sweep immediately. It is useful for
// deterministic tests and one-shot operational invocations; Run uses the same
// internal sweep path after maintaining leadership.
func (s *Sweeper) Sweep(ctx context.Context) (SweepResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var result SweepResult
	acquired, err := s.lease.TryAcquire(ctx)
	if err != nil {
		return result, err
	}
	if !acquired {
		return result, nil
	}
	result.Leader = true
	result, sweepErr := s.sweepLeader(ctx)
	releaseErr := s.release(ctx)
	return result, errors.Join(sweepErr, releaseErr)
}

// Run waits on injected ticker signals until ctx is canceled. Shutdown stops
// renewal, releases the lease with a bounded independent context, and returns
// promptly once the current rotation calls honor cancellation.
func (s *Sweeper) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	leader := false
	var lost <-chan struct{}
	var stopRenew func()
	defer func() {
		if stopRenew != nil {
			stopRenew()
		}
		if leader {
			if err := s.release(context.Background()); err != nil && !errors.Is(err, ErrLeaseNotHeld) {
				s.log("release lifecycle sweep lease: %v", err)
			}
		}
	}()

	for {
		delay := s.nextDelay()
		ticker := s.newTicker(delay)
		if ticker == nil {
			return errors.New("sweeper ticker factory returned nil")
		}
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil
		case <-ticker.C():
			ticker.Stop()
			if lost != nil {
				select {
				case <-lost:
					leader = false
					if stopRenew != nil {
						stopRenew()
						stopRenew = nil
					}
					lost = nil
				default:
				}
			}
			if !leader {
				acquired, err := s.lease.TryAcquire(ctx)
				if err != nil {
					s.log("acquire lifecycle sweep lease: %v", err)
					continue
				}
				if !acquired {
					continue
				}
				leader = true
				lost, stopRenew = s.startRenewal(ctx)
			}
			if leader {
				_, err := s.sweepLeader(ctx)
				if err != nil && !errors.Is(err, context.Canceled) {
					s.log("lifecycle sweep: %v", err)
				}
				if lost != nil {
					select {
					case <-lost:
						leader = false
						stopRenew()
						stopRenew = nil
						lost = nil
					default:
					}
				}
			}
		}
	}
}

func (s *Sweeper) sweepLeader(ctx context.Context) (SweepResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.clock().UTC()
	identities := s.store.List()
	candidates := make([]protocol.MachineIdentity, 0, len(identities))
	result := SweepResult{Leader: true}
	retryWindow := s.interval / 4
	if retryWindow <= 0 {
		retryWindow = time.Nanosecond
	}

	s.attemptMu.Lock()
	for _, identity := range identities {
		if identity.State != protocol.StateActive {
			result.Skipped++
			continue
		}
		if RenewalUrgency(identity, now) != protocol.UrgencyOverdue {
			result.Skipped++
			continue
		}
		if last, ok := s.lastAttempt[identity.ID]; ok && (now.Before(last) || now.Sub(last) < retryWindow) {
			result.Skipped++
			continue
		}
		s.lastAttempt[identity.ID] = now
		candidates = append(candidates, identity)
	}
	s.attemptMu.Unlock()
	result.Considered = len(candidates)
	if len(candidates) == 0 {
		return result, nil
	}

	jobs := make(chan protocol.MachineIdentity)
	var workers sync.WaitGroup
	var resultMu sync.Mutex
	workerCount := s.concurrency
	if workerCount > len(candidates) {
		workerCount = len(candidates)
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for identity := range jobs {
				select {
				case s.limiter <- struct{}{}:
				case <-ctx.Done():
					return
				}
				request := protocol.RotateRequest{
					ID:          identity.ID,
					RequestedBy: "system:sweeper",
					Reason:      fmt.Sprintf("scheduled renewal sweep %d", s.sweepSeq.Add(1)),
				}
				_, err := s.store.Rotate(ctx, request, s.clock().UTC())
				<-s.limiter
				resultMu.Lock()
				if err != nil {
					result.Failures = append(result.Failures, SweepFailure{IdentityID: identity.ID, Error: err})
					s.log("rotate overdue identity %s: %v", identity.ID, err)
				} else {
					result.Rotated++
				}
				resultMu.Unlock()
			}
		}()
	}
	for _, identity := range candidates {
		select {
		case jobs <- identity:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Sweeper) startRenewal(ctx context.Context) (<-chan struct{}, func()) {
	renewEvery := s.interval / 3
	if provider, ok := s.lease.(interface{ LeaseRenewInterval() time.Duration }); ok {
		renewEvery = provider.LeaseRenewInterval()
		if renewEvery <= 0 {
			return nil, func() {}
		}
	}
	if renewEvery <= 0 {
		renewEvery = time.Nanosecond
	}
	renewContext, cancel := context.WithCancel(ctx)
	lost := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := s.newTicker(renewEvery)
		if ticker == nil {
			lost <- struct{}{}
			return
		}
		defer ticker.Stop()
		for {
			select {
			case <-renewContext.Done():
				return
			case <-ticker.C():
				if err := s.lease.Renew(renewContext); err != nil {
					s.log("renew lifecycle sweep lease: %v", err)
					lost <- struct{}{}
					return
				}
			}
		}
	}()
	return lost, func() {
		cancel()
		<-done
	}
}

func (s *Sweeper) release(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.lease.Release(bounded)
}

func (s *Sweeper) nextDelay() time.Duration {
	extra := time.Duration(0)
	if s.jitter > 0 {
		random := s.random()
		if random < 0 {
			random = 0
		}
		if random > 1 {
			random = 1
		}
		extra = time.Duration(float64(s.jitter) * random)
	}
	return s.interval + extra
}

func (s *Sweeper) log(format string, args ...any) {
	if s.logger != nil {
		s.logger(format, args...)
	}
}
