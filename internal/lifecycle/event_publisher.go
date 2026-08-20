package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
	"github.com/redis/go-redis/v9"
)

// EventPublisher publishes redacted interactive operation events. It is
// separate from Repository because these events are notifications/receipts,
// not part of the durable lifecycle snapshot.
type EventPublisher interface {
	Publish(ctx context.Context, event protocol.AzureIntegrationEvent) error
}

// RedisEventPublisher atomically stores a short-lived redacted receipt and
// publishes its invalidation notification using Redis MULTI/EXEC. It never
// accepts secret material in the event type.
type RedisEventPublisher struct {
	client  *redis.Client
	channel string
	prefix  string
	ttl     time.Duration
}

func NewRedisEventPublisher(client *redis.Client, prefix string, ttl time.Duration) (*RedisEventPublisher, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), ":")
	if prefix == "" || strings.ContainsAny(prefix, " \t\r\n") {
		return nil, errors.New("event prefix is required and must not contain whitespace")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &RedisEventPublisher{client: client, prefix: prefix, channel: prefix + ":integration:changes", ttl: ttl}, nil
}

func (p *RedisEventPublisher) Publish(ctx context.Context, event protocol.AzureIntegrationEvent) error {
	if event.ID == "" || event.CorrelationID == "" || event.Type == "" {
		return errors.New("event id, type, and correlation id are required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode integration event: %w", err)
	}
	key := p.prefix + ":integration:event:" + event.ID
	if err := p.client.Watch(ctx, func(tx *redis.Tx) error {
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, payload, p.ttl)
			pipe.Publish(ctx, p.channel, event.ID)
			return nil
		})
		return err
	}); err != nil {
		return fmt.Errorf("publish integration event atomically: %w", err)
	}
	return nil
}

// MemoryEventPublisher is deterministic test infrastructure and deliberately
// keeps only redacted protocol events.
type MemoryEventPublisher struct {
	mu     sync.Mutex
	Events []protocol.AzureIntegrationEvent
}

func (p *MemoryEventPublisher) Publish(_ context.Context, event protocol.AzureIntegrationEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Events = append(p.Events, event)
	return nil
}
