package lifecycle

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
	"github.com/redis/go-redis/v9"
)

func TestRedisRepositoryRealServerSnapshotIsolationAndPubSub(t *testing.T) {
	url := os.Getenv("MUTANDAE_REDIS_TEST_URL")
	if url == "" {
		t.Skip("MUTANDAE_REDIS_TEST_URL is not set; run against the provisioned Redis endpoint")
	}
	clientOptions, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse MUTANDAE_REDIS_TEST_URL: %v", err)
	}
	client := redis.NewClient(clientOptions)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping test Redis: %v", err)
	}

	prefix := fmt.Sprintf("mutandae:test:%d", time.Now().UnixNano())
	defer deletePrefix(t, client, prefix)
	writer, err := NewRedisRepository(client, prefix+":writer")
	if err != nil {
		t.Fatalf("writer repository: %v", err)
	}
	reader, err := NewRedisRepository(client, prefix+":reader")
	if err != nil {
		t.Fatalf("reader repository: %v", err)
	}
	defer writer.Close()
	defer reader.Close()

	// Use the same prefix for the actual pub/sub assertion; the separate
	// repository above proves arbitrary prefixes are accepted and isolated.
	_ = writer.Close()
	_ = reader.Close()
	writer, err = NewRedisRepository(client, prefix)
	if err != nil {
		t.Fatalf("shared writer repository: %v", err)
	}
	reader, err = NewRedisRepository(client, prefix)
	if err != nil {
		t.Fatalf("shared reader repository: %v", err)
	}
	defer writer.Close()
	defer reader.Close()

	changes, err := reader.Changes(ctx)
	if err != nil {
		t.Fatalf("subscribe to changes: %v", err)
	}
	snapshot := Snapshot{Identities: []protocol.MachineIdentity{{ID: "test-identity", Name: "test-identity", State: protocol.StateActive, Health: protocol.HealthHealthy}}}
	if err := writer.Save(ctx, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	select {
	case <-changes:
	case <-ctx.Done():
		t.Fatal("timed out waiting for Redis pub/sub change")
	}
	loaded, err := reader.Load(ctx)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if len(loaded.Identities) != 1 || loaded.Identities[0].ID != "test-identity" {
		t.Fatalf("loaded snapshot = %+v, want isolated test identity", loaded)
	}

	otherPrefix := prefix + ":other"
	defer deletePrefix(t, client, otherPrefix)
	other, err := NewRedisRepository(client, otherPrefix)
	if err != nil {
		t.Fatalf("other repository: %v", err)
	}
	defer other.Close()
	if _, err := other.Load(ctx); err != ErrNoSnapshot {
		t.Fatalf("other prefix Load() error = %v, want ErrNoSnapshot", err)
	}
}

func deletePrefix(t *testing.T, client *redis.Client, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var cursor uint64
	pattern := strings.TrimSuffix(prefix, ":") + ":*"
	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			t.Logf("cleanup scan %q: %v", pattern, err)
			return
		}
		if len(keys) > 0 {
			if err := client.Del(ctx, keys...).Err(); err != nil {
				t.Logf("cleanup delete %q: %v", pattern, err)
			}
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}
