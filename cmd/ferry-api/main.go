// ferry-api serves the ferry ticketing, NIMASA manifest and operator portal
// APIs. Configuration is environment-driven and fail-closed: the process
// refuses to start without PostgreSQL, TigerBeetle, the manifest salt and a
// fully specified auth mode.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/config"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/httpapi"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("ferry-api failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	telemetryConfig, err := telemetry.LoadConfig("blueeconomy-ferry-ticketing")
	if err != nil {
		return fmt.Errorf("load telemetry config: %w", err)
	}
	pipeline, err := telemetry.Setup(ctx, telemetryConfig)
	if err != nil {
		return fmt.Errorf("setup telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := pipeline.Shutdown(shutdownCtx); err != nil {
			logger.Error("telemetry shutdown failed", "error", err.Error())
		}
	}()
	if pipeline.Enabled() {
		logger.Info("telemetry enabled", "otlp_endpoint", telemetryConfig.Endpoint, "metrics", "GET /metrics")
	} else {
		logger.Info("telemetry tracing disabled (OTEL_EXPORTER_OTLP_ENDPOINT not set); explicit no-op tracer active, Prometheus metrics on GET /metrics")
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	var authenticator auth.Authenticator
	switch cfg.AuthMode {
	case "jwt":
		authenticator, err = auth.NewOIDCAuthenticator(cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCJWKSURL, cfg.OIDCCAFile)
		if err != nil {
			return fmt.Errorf("configure OIDC authenticator: %w", err)
		}
	case "trusted_proxy":
		authenticator = auth.TrustedProxyAuthenticator{CIDRs: cfg.TrustedProxyCIDRs, Identity: cfg.TrustedProxyIdentity}
	default:
		return fmt.Errorf("auth mode %q is not supported", cfg.AuthMode)
	}

	tbClient, err := tigerbeetle.NewClient(tigerbeetle.ToUint128(uint64(cfg.TigerBeetleClusterID)), []string{cfg.TigerBeetleAddress})
	if err != nil {
		return fmt.Errorf("connect TigerBeetle: %w", err)
	}
	defer tbClient.Close()
	clearing, err := ledger.ParseID(cfg.PassengerClearingAccount)
	if err != nil {
		return fmt.Errorf("FERRY_TB_PASSENGER_CLEARING_ACCOUNT: %w", err)
	}
	revenue, err := ledger.ParseID(cfg.OperatorRevenueAccount)
	if err != nil {
		return fmt.Errorf("FERRY_TB_OPERATOR_REVENUE_ACCOUNT: %w", err)
	}
	agentFloat, err := ledger.ParseID(cfg.AgentFloatAccount)
	if err != nil {
		return fmt.Errorf("FERRY_TB_AGENT_FLOAT_ACCOUNT: %w", err)
	}
	ledgerService, err := ledger.New(tbClient, ledger.Topology{
		Ledger:                   cfg.TigerBeetleLedger,
		Code:                     cfg.TigerBeetleCode,
		PassengerClearingAccount: clearing,
		OperatorRevenueAccount:   revenue,
		AgentFloatAccount:        agentFloat,
		PendingTimeoutSeconds:    cfg.PendingTransferTimeoutSeconds,
	})
	if err != nil {
		return fmt.Errorf("configure ledger: %w", err)
	}
	if err := ledgerService.EnsureAccounts(); err != nil {
		return fmt.Errorf("ensure ledger accounts: %w", err)
	}

	ticketStore, err := ticketing.NewPostgresStore(pool)
	if err != nil {
		return err
	}
	manifestStore, err := manifest.NewPostgresStore(pool)
	if err != nil {
		return err
	}
	ticketService, err := ticketing.NewService(ticketStore, ledgerService, cfg.ManifestSalt)
	if err != nil {
		return err
	}
	server, err := httpapi.NewServer(authenticator, ticketService, ticketStore, manifestStore, cfg.ManifestSalt, cfg.CompletenessKPI, logger,
		func(ctx context.Context) error { return pool.Ping(ctx) }, pipeline)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	logger.Info("ferry-api listening", "address", cfg.ListenAddress)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}
