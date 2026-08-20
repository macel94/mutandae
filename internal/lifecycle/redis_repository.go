package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

const snapshotVersion = "v1"

// RedisRepository stores one JSON snapshot per logical demo environment and
// uses Redis Pub/Sub to invalidate in-process readers. Prefix is mandatory so
// preview and live can safely share one Redis server without sharing keys.
type RedisRepository struct {
	client    *redis.Client
	prefix    string
	snapshot  string
	channel   string
	mu        sync.Mutex
	closed    bool
	listeners map[*redisListener]struct{}
	pubsub    *redis.PubSub
	cancel    context.CancelFunc
	done      chan struct{}
}

type redisSnapshot struct {
	Version string   `json:"version"`
	State   Snapshot `json:"state"`
}

type redisListener struct {
	ch   chan struct{}
	once sync.Once
}

// NewRedisRepository constructs a repository using an existing Redis client.
// prefix must identify an isolated environment, for example "mutandae:live".
func NewRedisRepository(client *redis.Client, prefix string) (*RedisRepository, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), ":")
	if prefix == "" || strings.ContainsAny(prefix, " \t\r\n") {
		return nil, errors.New("redis key prefix is required and must not contain whitespace")
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &RedisRepository{
		client:    client,
		prefix:    prefix,
		snapshot:  prefix + ":snapshot",
		channel:   prefix + ":changes",
		listeners: make(map[*redisListener]struct{}),
		done:      make(chan struct{}),
		cancel:    cancel,
	}
	r.pubsub = client.Subscribe(ctx, r.channel)
	go r.consume(ctx)
	return r, nil
}

func (r *RedisRepository) Load(ctx context.Context) (Snapshot, error) {
	payload, err := r.client.Get(ctx, r.snapshot).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Snapshot{}, ErrNoSnapshot
		}
		return Snapshot{}, fmt.Errorf("%w: load redis snapshot: %v", ErrPersistenceFailure, err)
	}
	var stored redisSnapshot
	if err := json.Unmarshal(payload, &stored); err != nil {
		return Snapshot{}, fmt.Errorf("%w: decode redis snapshot: %v", ErrPersistenceFailure, err)
	}
	if stored.Version != snapshotVersion {
		return Snapshot{}, fmt.Errorf("%w: unsupported snapshot version %q", ErrPersistenceFailure, stored.Version)
	}
	return stored.State, nil
}

func (r *RedisRepository) Save(ctx context.Context, snapshot Snapshot) error {
	payload, err := json.Marshal(redisSnapshot{Version: snapshotVersion, State: snapshot})
	if err != nil {
		return fmt.Errorf("%w: encode redis snapshot: %v", ErrPersistenceFailure, err)
	}
	if err := r.client.Set(ctx, r.snapshot, payload, 0).Err(); err != nil {
		return fmt.Errorf("%w: save redis snapshot: %v", ErrPersistenceFailure, err)
	}
	if err := r.client.Publish(ctx, r.channel, "changed").Err(); err != nil {
		return fmt.Errorf("%w: publish redis change: %v", ErrPersistenceFailure, err)
	}
	return nil
}

func (r *RedisRepository) Changes(ctx context.Context) (<-chan struct{}, error) {
	listener := &redisListener{ch: make(chan struct{}, 1)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("redis repository is closed")
	}
	r.listeners[listener] = struct{}{}
	go func() {
		<-ctx.Done()
		r.removeListener(listener)
	}()
	return listener.ch, nil
}

func (r *RedisRepository) removeListener(listener *redisListener) {
	r.mu.Lock()
	delete(r.listeners, listener)
	r.mu.Unlock()
	listener.once.Do(func() { close(listener.ch) })
}

func (r *RedisRepository) consume(ctx context.Context) {
	defer close(r.done)
	messages := r.pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-messages:
			if !ok {
				return
			}
			r.mu.Lock()
			for listener := range r.listeners {
				select {
				case listener.ch <- struct{}{}:
				default:
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *RedisRepository) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	listeners := make([]*redisListener, 0, len(r.listeners))
	for listener := range r.listeners {
		listeners = append(listeners, listener)
	}
	r.listeners = nil
	r.mu.Unlock()
	for _, listener := range listeners {
		listener.once.Do(func() { close(listener.ch) })
	}

	r.cancel()
	_ = r.pubsub.Close()
	<-r.done
	return nil
}
