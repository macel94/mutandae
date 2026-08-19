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
	"github.com/mutandae/mutandae/internal/web"
)

func main() {
	port := envInt("PORT", 8080)
	store := lifecycle.NewDemoStore(time.Now())
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
