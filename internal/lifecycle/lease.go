package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrLeaseNotHeld = errors.New("lease is not held by this instance")
	ErrLeaseConfig  = errors.New("invalid lease configuration")
)

// LeaseManager is the leader-election boundary used by the lifecycle worker.
// TryAcquire returns false when another instance currently owns the lease.
type LeaseManager interface {
	TryAcquire(ctx context.Context) (bool, error)
	Renew(ctx context.Context) error
	Release(ctx context.Context) error
}

// InMemoryLeaseManager is the single-process leader implementation. A process
// without Redis is intentionally treated as the sole instance.
type InMemoryLeaseManager struct{}

func NewInMemoryLeaseManager() *InMemoryLeaseManager { return &InMemoryLeaseManager{} }

func (*InMemoryLeaseManager) TryAcquire(context.Context) (bool, error) { return true, nil }
func (*InMemoryLeaseManager) Renew(context.Context) error              { return nil }
func (*InMemoryLeaseManager) Release(context.Context) error            { return nil }
func (*InMemoryLeaseManager) LeaseRenewInterval() time.Duration        { return 0 }

// RedisLeaseManager owns one Redis key using a unique value per instance.
// The value is never accepted from a caller during renewal or release, so an
// expired lease cannot be deleted or extended by its former owner.
type RedisLeaseManager struct {
	client *redis.Client
	key    string
	value  string
	ttl    time.Duration
}

func NewRedisLeaseManager(client *redis.Client, key, instanceID string, ttl time.Duration) (*RedisLeaseManager, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: redis client is required", ErrLeaseConfig)
	}
	key = strings.TrimSpace(key)
	instanceID = strings.TrimSpace(instanceID)
	if key == "" || instanceID == "" || strings.ContainsAny(key+instanceID, " \t\r\n") {
		return nil, fmt.Errorf("%w: lease key and instance id are required and cannot contain whitespace", ErrLeaseConfig)
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: lease TTL must be positive", ErrLeaseConfig)
	}
	if ttl.Milliseconds() <= 0 {
		return nil, fmt.Errorf("%w: lease TTL must be at least one millisecond", ErrLeaseConfig)
	}
	return &RedisLeaseManager{client: client, key: key, value: instanceID, ttl: ttl}, nil
}

func (m *RedisLeaseManager) TryAcquire(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	acquired, err := m.client.SetNX(ctx, m.key, m.value, m.ttl).Result()
	if err != nil {
		return false, fmt.Errorf("acquire Redis lease: %w", err)
	}
	return acquired, nil
}

func (m *RedisLeaseManager) Renew(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := m.client.Eval(ctx, renewLeaseScript, []string{m.key}, m.value, m.ttl.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("renew Redis lease: %w", err)
	}
	if result != 1 {
		return ErrLeaseNotHeld
	}
	return nil
}

func (m *RedisLeaseManager) Release(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := m.client.Eval(ctx, releaseLeaseScript, []string{m.key}, m.value).Int()
	if err != nil {
		return fmt.Errorf("release Redis lease: %w", err)
	}
	if result != 1 {
		return ErrLeaseNotHeld
	}
	return nil
}

// LeaseRenewInterval lets the worker honor the Redis lease's TTL/3 cadence
// without expanding the small LeaseManager interface used by fakes.
func (m *RedisLeaseManager) LeaseRenewInterval() time.Duration {
	interval := m.ttl / 3
	if interval <= 0 {
		return time.Millisecond
	}
	return interval
}

const renewLeaseScript = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("pexpire", KEYS[1], ARGV[2])
end
return 0
`

const releaseLeaseScript = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
end
return 0
`
