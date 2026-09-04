package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisLeaseManagerRequiresConfiguration(t *testing.T) {
	if _, err := NewRedisLeaseManager(nil, "key", "instance", time.Second); !errors.Is(err, ErrLeaseConfig) {
		t.Fatalf("nil client error = %v, want ErrLeaseConfig", err)
	}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	defer client.Close()
	for _, test := range []struct {
		key, instance string
		ttl           time.Duration
	}{
		{"", "instance", time.Second},
		{"key", "", time.Second},
		{"key with space", "instance", time.Second},
		{"key", "instance", 0},
	} {
		if _, err := NewRedisLeaseManager(client, test.key, test.instance, test.ttl); !errors.Is(err, ErrLeaseConfig) {
			t.Errorf("config (%q,%q,%s) error = %v, want ErrLeaseConfig", test.key, test.instance, test.ttl, err)
		}
	}
}

func TestRedisLeaseRealServerOwnershipAndRelease(t *testing.T) {
	url := os.Getenv("MUTANDAE_REDIS_TEST_URL")
	if url == "" {
		t.Skip("MUTANDAE_REDIS_TEST_URL is not set; run against the provisioned Redis endpoint")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse MUTANDAE_REDIS_TEST_URL: %v", err)
	}
	client := redis.NewClient(options)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping test Redis: %v", err)
	}

	key := fmt.Sprintf("mutandae:test:lifecycle:lease:%d", time.Now().UnixNano())
	defer client.Del(context.Background(), key)
	first, err := NewRedisLeaseManager(client, key, "instance-a", 5*time.Second)
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	second, err := NewRedisLeaseManager(client, key, "instance-b", 5*time.Second)
	if err != nil {
		t.Fatalf("second lease: %v", err)
	}
	acquired, err := first.TryAcquire(ctx)
	if err != nil || !acquired {
		t.Fatalf("first TryAcquire = (%v, %v), want (true, nil)", acquired, err)
	}
	acquired, err = second.TryAcquire(ctx)
	if err != nil || acquired {
		t.Fatalf("second TryAcquire = (%v, %v), want (false, nil)", acquired, err)
	}
	if err := first.Renew(ctx); err != nil {
		t.Fatalf("first Renew: %v", err)
	}
	if err := second.Renew(ctx); !errors.Is(err, ErrLeaseNotHeld) {
		t.Fatalf("second Renew = %v, want ErrLeaseNotHeld", err)
	}
	if err := second.Release(ctx); !errors.Is(err, ErrLeaseNotHeld) {
		t.Fatalf("second Release = %v, want ErrLeaseNotHeld", err)
	}
	if err := first.Release(ctx); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	acquired, err = second.TryAcquire(ctx)
	if err != nil || !acquired {
		t.Fatalf("second TryAcquire after release = (%v, %v), want (true, nil)", acquired, err)
	}
	if err := second.Release(ctx); err != nil {
		t.Fatalf("second final Release: %v", err)
	}
}
