package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	// control plane. The demo starts from three simulated cloud providers
	// (Azure/Entra ID, AWS IAM, GCP IAM) fused into one multi-cloud adapter, which
	// the control plane discovers and governs over the μTandae Protocol.
	now := time.Now
	startedAt := now()
	environment := envString("MUTANDAE_ENVIRONMENT", "preview")
	tenantID := envString("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo")
	awsAccountID := envString("MUTANDAE_AWS_ACCOUNT", "123456789012")
	awsRegion := envString("MUTANDAE_AWS_REGION", "us-east-1")
	gcpProjectID := envString("MUTANDAE_GCP_PROJECT", "mutandae-demo")
	gcpRegion := envString("MUTANDAE_GCP_REGION", "us-central1")

	// Real adapters are wired at the composition root when credential
	// environment variables are present. In the live environment a missing
	// credential set is a hard error: the public site must never silently fall
	// back to a simulator that pretends to be a real tenant. In preview/local
	// mode the simulator stays available for development and tests.
	azureAdapter, azureLabel, azureReal, err := wireAzureAdapter(now)
	if err != nil {
		log.Fatalf("wire Azure adapter: %v", err)
	}
	awsAdapter, awsLabel, awsReal, err := wireAWSAdapter(now, awsAccountID, awsRegion)
	if err != nil {
		log.Fatalf("wire AWS adapter: %v", err)
	}
	gcpAdapter, gcpLabel, gcpReal, err := wireGCPAdapter(now, gcpProjectID, gcpRegion)
	if err != nil {
		log.Fatalf("wire GCP adapter: %v", err)
	}

	provisionFeatures := []string{}
	if azureReal {
		provisionFeatures = append(provisionFeatures, "provision:azure-entra")
	}
	if awsReal {
		provisionFeatures = append(provisionFeatures, "provision:aws-iam")
	}
	if gcpReal {
		provisionFeatures = append(provisionFeatures, "provision:gcp-iam")
	}

	adapter, err := provider.NewMultiProvider(
		azureAdapter,
		awsAdapter,
		gcpAdapter,
	)
	if err != nil {
		log.Fatalf("wire multi-cloud provider adapters: %v", err)
	}
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
	var integration lifecycle.IntegrationService
	var events lifecycle.EventPublisher
	if redisClient != nil {
		events, err = lifecycle.NewRedisEventPublisher(redisClient, redisPrefix(), 24*time.Hour)
		if err != nil {
			log.Fatalf("create integration event publisher: %v", err)
		}
	} else {
		events = &lifecycle.MemoryEventPublisher{}
	}
	integration, err = lifecycle.NewIntegrationManager(events, nil, now, 10*time.Minute)
	if err != nil {
		log.Fatalf("create Azure integration manager: %v", err)
	}

	handler, err := web.NewServer(web.Dependencies{
		Lifecycle:   store,
		Integration: integration,
		Configuration: config.Public{
			Environment: environment,
			Persistence: persistenceLabel(repository),
			Provider:    "multi-cloud (azure-entra " + azureLabel + ", aws-iam " + awsLabel + ", gcp-iam " + gcpLabel + ")",
			Clock:       now,
			Features:    provisionFeatures,
		},
		Clock:  now,
		Logger: log.Default(),
		RateLimit: web.RateLimitConfig{
			ReadRate:    envFloat("MUTANDAE_RATE_READ_PER_SEC", 10),
			ReadBurst:   envInt("MUTANDAE_RATE_READ_BURST", 60),
			WriteRate:   envFloat("MUTANDAE_RATE_WRITE_PER_SEC", 1),
			WriteBurst:  envInt("MUTANDAE_RATE_WRITE_BURST", 10),
			CreateRate:  envFloat("MUTANDAE_RATE_CREATE_PER_SEC", 0.1),
			CreateBurst: envInt("MUTANDAE_RATE_CREATE_BURST", 2),
		},
		DemoLimit: envInt("MUTANDAE_DEMO_LIMIT", 40),
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
		log.Printf("Provider adapters: azure-entra (tenant %s), aws-iam (account %s), gcp-iam (project %s)", tenantID, awsAccountID, gcpProjectID)
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
	if integration != nil {
		integration.Close()
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

func envFloat(name string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 {
		log.Printf("invalid %s=%q; using %g", name, value, fallback)
		return fallback
	}
	return parsed
}

// wireAWSAdapter returns a real AWS IAM adapter when AWS_ACCESS_KEY_ID and
// AWS_SECRET_ACCESS_KEY are present in the environment, and the public
// simulator otherwise. The returned label describes what is wired for the
// configuration page without revealing any secret, and real reports whether a
// live tenant is governed (which also enables provisioning).
func wireAWSAdapter(now func() time.Time, fallbackAccountID, fallbackRegion string) (provider.CloudAdapter, string, bool, error) {
	accountID := envString("AWS_ACCOUNT_ID", fallbackAccountID)
	accessKeyID := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKeyID == "" || secretKey == "" {
		if isLive() {
			return nil, "", false, errors.New("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are required in the live environment")
		}
		return provider.NewAWSSimulator(accountID, envString("AWS_REGION", fallbackRegion), now()), "simulated", false, nil
	}
	adapter, err := provider.NewAWSAdapter(provider.AWSAdapterConfig{
		AccountID:    accountID,
		Region:       envString("AWS_REGION", fallbackRegion),
		AccessKeyID:  accessKeyID,
		SecretKey:    secretKey,
		SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		Now:          now,
		DemoOnly:     true, // live demo governs only mutandae-demo-* identities
	})
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

// wireGCPAdapter returns a real GCP IAM adapter when
// GCP_SERVICE_ACCOUNT_KEY_JSON (or GCP_SERVICE_ACCOUNT_KEY_FILE) is present,
// and the public simulator otherwise.
func wireGCPAdapter(now func() time.Time, fallbackProjectID, fallbackRegion string) (provider.CloudAdapter, string, bool, error) {
	projectID := envString("GCP_PROJECT_ID", fallbackProjectID)
	keyJSON, keyErr := gcpKeyJSON()
	if keyErr != nil {
		return nil, "", false, keyErr
	}
	if keyJSON == "" {
		if isLive() {
			return nil, "", false, errors.New("GCP_SERVICE_ACCOUNT_KEY_JSON / GCP_SERVICE_ACCOUNT_KEY_FILE are required in the live environment")
		}
		return provider.NewGCPSimulator(projectID, envString("GCP_REGION", fallbackRegion), now()), "simulated", false, nil
	}
	adapter, err := provider.NewGCPAdapter(provider.GCPAdapterConfig{
		ProjectID: projectID,
		Region:    envString("GCP_REGION", fallbackRegion),
		KeyJSON:   keyJSON,
		Now:       now,
		DemoOnly:  true, // live demo governs only mutandae-demo-* identities
	})
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

// wireAzureAdapter returns a real Azure / Entra Graph adapter when
// AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are present, and the
// public simulator otherwise.
func wireAzureAdapter(now func() time.Time) (provider.CloudAdapter, string, bool, error) {
	tenantID := strings.TrimSpace(os.Getenv("AZURE_TENANT_ID"))
	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		if isLive() {
			return nil, "", false, errors.New("AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are required in the live environment")
		}
		return provider.NewSimulator(envString("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo"), now()), "simulated", false, nil
	}
	adapter, err := provider.NewAzureCloudAdapter(provider.AzureCloudAdapterConfig{
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Now:          now,
	})
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

func isLive() bool {
	return strings.EqualFold(envString("MUTANDAE_ENVIRONMENT", "preview"), "live")
}

func gcpKeyJSON() (string, error) {
	if value := os.Getenv("GCP_SERVICE_ACCOUNT_KEY_JSON"); value != "" {
		return value, nil
	}
	if keyFile := os.Getenv("GCP_SERVICE_ACCOUNT_KEY_FILE"); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("read GCP service account key file: %w", err)
		}
		return string(data), nil
	}
	return "", nil
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
