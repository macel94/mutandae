package main

import (
	"context"
	"encoding/hex"
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
	authConfig, err := authConfigFromEnv()
	if err != nil {
		log.Fatalf("read authentication configuration: %v", err)
	}
	if err := config.ValidateAuthMode(environment, authConfig.Mode); err != nil {
		log.Fatalf("validate authentication configuration: %v", err)
	}
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
	// Vault delivery: when enabled (MUTANDAE_VAULT != "off"), provisioned and
	// renewed demo credentials are delivered to the provider's native vault —
	// AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault (the latter
	// requires AZURE_KEY_VAULT_URL plus the documented Key Vault role).
	vaultEnabled := !strings.EqualFold(envString("MUTANDAE_VAULT", "auto"), "off")
	azureVaultURL := envString("AZURE_KEY_VAULT_URL", "")
	azureVaultPrefix := envString("AZURE_KEY_VAULT_PREFIX", "mutandae")

	azureAdapter, azureLabel, azureReal, err := wireAzureAdapter(now, azureVaultURL, azureVaultPrefix, vaultEnabled)
	if err != nil {
		log.Fatalf("wire Azure adapter: %v", err)
	}
	awsAdapter, awsLabel, awsReal, err := wireAWSAdapter(now, awsAccountID, awsRegion, vaultEnabled)
	if err != nil {
		log.Fatalf("wire AWS adapter: %v", err)
	}
	gcpAdapter, gcpLabel, gcpReal, err := wireGCPAdapter(now, gcpProjectID, gcpRegion, vaultEnabled)
	if err != nil {
		log.Fatalf("wire GCP adapter: %v", err)
	}

	provisionFeatures := []string{}
	if azureReal {
		provisionFeatures = append(provisionFeatures, "provision:azure-entra")
		if azureVaultURL != "" && vaultEnabled {
			provisionFeatures = append(provisionFeatures, "vault:azure-entra")
		}
	}
	if awsReal {
		provisionFeatures = append(provisionFeatures, "provision:aws-iam")
		if vaultEnabled {
			provisionFeatures = append(provisionFeatures, "vault:aws-iam")
		}
	}
	if gcpReal {
		provisionFeatures = append(provisionFeatures, "provision:gcp-iam")
		if vaultEnabled {
			provisionFeatures = append(provisionFeatures, "vault:gcp-iam")
		}
	}

	// Cluster-local μVault (HashiCorp Vault KV v2): the common vault where
	// demo credentials persist in the cluster. Wired when VAULT_ADDR and
	// VAULT_TOKEN are both present; in the live environment a half-wired
	// vault address/token pair is a hard error so the demo never advertises
	// more than it can do.
	commonVault, err := wireCommonVaultStore(now)
	if err != nil {
		log.Fatalf("wire cluster μVault store: %v", err)
	}
	var storeOptions []lifecycle.Option
	if commonVault != nil {
		storeOptions = append(storeOptions, lifecycle.WithCommonVault(commonVault))
		provisionFeatures = append(provisionFeatures, "vault:cluster")
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
		store, err = lifecycle.NewPersistentStore(context.Background(), startedAt, adapter, repository, storeOptions...)
	} else {
		store, err = lifecycle.NewStore(context.Background(), startedAt, adapter, storeOptions...)
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
		Auth:        authConfig,
		Metrics:     web.MetricsConfig{Enabled: true},
		Configuration: config.Public{
			Environment:      environment,
			AuthMode:         authConfig.Mode,
			AuthRoles:        []string{web.RoleAdmin, web.RoleOperator, web.RoleViewer},
			TokensConfigured: strings.TrimSpace(authConfig.APIToken) != "" || strings.TrimSpace(authConfig.APITokensFile) != "",

			Persistence: persistenceLabel(repository),
			Provider:    "multi-cloud (azure-entra " + azureLabel + ", aws-iam " + awsLabel + ", gcp-iam " + gcpLabel + ")",
			// Public, non-secret tenant scopes: the footer names the exact
			// Azure tenant, AWS account, and GCP project each adapter
			// governs. Identifiers of this kind are not credentials; they
			// already ride in tokens and ARNs.
			Providers: []config.ProviderDescriptor{
				{Kind: "azure-entra", Label: "Azure / Entra ID", Scope: "tenant " + azureScopeTenantID(tenantID)},
				{Kind: "aws-iam", Label: "AWS IAM", Scope: "account " + envString("AWS_ACCOUNT_ID", awsAccountID)},
				{Kind: "gcp-iam", Label: "GCP IAM", Scope: "project " + envString("GCP_PROJECT_ID", gcpProjectID)},
			},
			Clock:    now,
			Features: provisionFeatures,
		},
		Clock: now,
		// The request logger emits JSON lines; disabling log.Logger's prefix
		// keeps each emitted record valid JSON while startup logs retain the
		// process-wide standard logger below.
		Logger: log.New(os.Stderr, "", 0),
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

func authConfigFromEnv() (web.AuthConfig, error) {
	keyText := strings.TrimSpace(os.Getenv("MUTANDAE_SESSION_KEY"))
	var sessionKey []byte
	if keyText != "" {
		decoded, err := hex.DecodeString(keyText)
		if err != nil {
			return web.AuthConfig{}, fmt.Errorf("MUTANDAE_SESSION_KEY must be hexadecimal: %w", err)
		}
		if len(decoded) < 16 {
			return web.AuthConfig{}, errors.New("MUTANDAE_SESSION_KEY must contain at least 16 bytes")
		}
		sessionKey = decoded
	}
	mode := strings.ToLower(strings.TrimSpace(envString("MUTANDAE_AUTH_MODE", web.AuthModeNone)))
	if mode == "" {
		mode = web.AuthModeNone
	}
	return web.AuthConfig{
		Mode:          mode,
		IssuerURL:     envString("MUTANDAE_OIDC_ISSUER_URL", ""),
		ClientID:      envString("MUTANDAE_OIDC_CLIENT_ID", ""),
		ClientSecret:  os.Getenv("MUTANDAE_OIDC_CLIENT_SECRET"),
		RedirectURL:   envString("MUTANDAE_OIDC_REDIRECT_URL", ""),
		Scopes:        envString("MUTANDAE_OIDC_SCOPES", "openid profile email"),
		APIToken:      os.Getenv("MUTANDAE_API_TOKEN"),
		APITokensFile: envString("MUTANDAE_API_TOKENS_FILE", ""),
		SessionKey:    sessionKey,
	}, nil
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
func wireAWSAdapter(now func() time.Time, fallbackAccountID, fallbackRegion string, vaultEnabled bool) (provider.CloudAdapter, string, bool, error) {
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
		AccountID:      accountID,
		Region:         envString("AWS_REGION", fallbackRegion),
		AccessKeyID:    accessKeyID,
		SecretKey:      secretKey,
		SessionToken:   os.Getenv("AWS_SESSION_TOKEN"),
		Now:            now,
		DemoOnly:       true, // live demo governs only mutandae-demo-* identities
		SecretsManager: vaultEnabled,
	})
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

// wireGCPAdapter returns a real GCP IAM adapter when
// GCP_SERVICE_ACCOUNT_KEY_JSON (or GCP_SERVICE_ACCOUNT_KEY_FILE) is present,
// and the public simulator otherwise.
func wireGCPAdapter(now func() time.Time, fallbackProjectID, fallbackRegion string, vaultEnabled bool) (provider.CloudAdapter, string, bool, error) {
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
		ProjectID:     projectID,
		Region:        envString("GCP_REGION", fallbackRegion),
		KeyJSON:       keyJSON,
		Now:           now,
		DemoOnly:      true, // live demo governs only mutandae-demo-* identities
		SecretManager: vaultEnabled,
	})
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

// wireAzureAdapter returns a real Azure / Entra Graph adapter when
// AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are present, and the
// public simulator otherwise. When vaultURL is set (and enabled), the adapter
// additionally delivers credentials to that existing Key Vault.
func wireAzureAdapter(now func() time.Time, vaultURL, vaultPrefix string, vaultEnabled bool) (provider.CloudAdapter, string, bool, error) {
	tenantID := strings.TrimSpace(os.Getenv("AZURE_TENANT_ID"))
	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		if isLive() {
			return nil, "", false, errors.New("AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are required in the live environment")
		}
		return provider.NewSimulator(envString("MUTANDAE_TENANT", "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo"), now()), "simulated", false, nil
	}
	cfg := provider.AzureCloudAdapterConfig{
		TenantID:          tenantID,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		Now:               now,
		VaultSecretPrefix: vaultPrefix,
	}
	if vaultEnabled {
		cfg.VaultURL = vaultURL
	}
	adapter, err := provider.NewAzureCloudAdapter(cfg)
	if err != nil {
		return nil, "", false, err
	}
	return adapter, "real", true, nil
}

// azureScopeTenantID resolves the Azure tenant identifier the demo actually
// governs: the real tenant when a Graph credential is wired, the synthetic
// simulator label otherwise.
func azureScopeTenantID(fallback string) string {
	if tenantID := strings.TrimSpace(os.Getenv("AZURE_TENANT_ID")); tenantID != "" {
		return tenantID
	}
	return fallback
}

// wireCommonVaultStore returns the cluster-local HashiCorp Vault KV v2 store
// when VAULT_ADDR and VAULT_TOKEN are both present, and nil (feature off)
// otherwise. A half-configured pair is a misconfiguration: in the live
// environment it fails startup, elsewhere it logs and disables the mirror.
func wireCommonVaultStore(now func() time.Time) (lifecycle.CommonVault, error) {
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	token := os.Getenv("VAULT_TOKEN")
	if addr == "" && token == "" {
		return nil, nil
	}
	store, err := provider.NewHashiCorpVault(provider.HashiCorpVaultConfig{
		Addr:   addr,
		Token:  token,
		Mount:  envString("VAULT_MOUNT", "mutandae"),
		Prefix: envString("VAULT_SECRET_PREFIX", "demo"),
		Now:    now,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
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
