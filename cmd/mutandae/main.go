package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mutandae/mutandae/internal/config"
	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/internal/web"
	"github.com/redis/go-redis/v9"
)

func main() {
	port := envInt("PORT", 8080)

	// Composition root: wire the provider-aware execution boundary to the
	// control plane. The demo starts from Azure: a simulated Entra ID tenant
	// exposes its application registrations, which the control plane discovers
	// and governs over the μTandae Protocol.
	now := time.Now
	startedAt := now()
	tenantID := envString("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo")
	adapter := provider.NewSimulator(tenantID, startedAt)
	var store *lifecycle.Store
	var repository lifecycle.Repository
	redisClient, redisClose, err := openRedisRepository()
	if err != nil {
		log.Fatalf("initialise Redis persistence: %v", err)
	}
	if redisClient != nil {
		defer redisClose()
		repository, err = lifecycle.NewRedisRepository(redisClient, redisPrefix())
		if err != nil {
			log.Fatalf("create Redis repository: %v", err)
		}
		store, err = lifecycle.NewPersistentStore(context.Background(), startedAt, adapter, repository)
	} else {
		store, err = lifecycle.NewStore(context.Background(), startedAt, adapter)
	}
	if err != nil {
		log.Fatalf("initialise control plane: %v", err)
	}

	handler, err := web.NewServer(web.Dependencies{
		Lifecycle: store,
		Configuration: config.Public{
			Environment: envString("MUTANDAE_ENVIRONMENT", "preview"),
			Persistence: persistenceLabel(repository),
			Provider:    "azure-entra (simulated)",
			Clock:       now,
		},
		Clock:  now,
		Logger: log.Default(),
	})
	if err != nil {
		log.Fatalf("create web server: %v", err)
	}

	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("Mutandae demo listening on http://localhost:%d (Classical Latin: moo-TAHN-dye)", port)
		log.Printf("Provider adapter: %s (simulated tenant %s)", adapter.Kind(), tenantID)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down")
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("graceful shutdown: %v", err)
	}
	if err := store.Close(); err != nil {
		log.Printf("close lifecycle store: %v", err)
	}
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		log.Printf("invalid %s=%q; using %d", name, value, fallback)
		return fallback
	}
	return port
}

func envString(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func redisPrefix() string {
	return "mutandae:" + envString("MUTANDAE_ENVIRONMENT", "preview")
}

func persistenceLabel(repository lifecycle.Repository) string {
	if repository != nil {
		return "redis"
	}
	return "in-memory"
}

func openRedisRepository() (*redis.Client, func(), error) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, func() {}, nil
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, func() {}, fmt.Errorf("parse REDIS_URL: %w", err)
	}
	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, func() {}, fmt.Errorf("ping Redis: %w", err)
	}
	return client, func() { _ = client.Close() }, nil
}
