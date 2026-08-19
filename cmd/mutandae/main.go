package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/internal/web"
)

func main() {
	port := envInt("PORT", 8080)

	// Composition root: wire the provider-aware execution boundary to the
	// control plane. The demo starts from Azure: a simulated Entra ID tenant
	// exposes its application registrations, which the control plane discovers
	// and governs over the μTandae Protocol.
	now := time.Now()
	tenantID := envString("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo")
	adapter := provider.NewSimulator(tenantID, now)
	store, err := lifecycle.NewStore(context.Background(), now, adapter)
	if err != nil {
		log.Fatalf("initialise control plane: %v", err)
	}

	handler, err := web.NewServer(web.Dependencies{
		Lifecycle: store,
		Clock:     time.Now,
		Logger:    log.Default(),
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
