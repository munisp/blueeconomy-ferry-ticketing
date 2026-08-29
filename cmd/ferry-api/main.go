// ferry-api serves the ferry ticketing, NIMASA manifest and operator portal
// APIs. Configuration is environment-driven and fail-closed: the process
// refuses to start without PostgreSQL, TigerBeetle, the manifest salt and a
// fully specified auth mode.
package main

import (
	"context"
	"crypto/ed25519"
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
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/fare"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/httpapi"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/passproof"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
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
		// Telemetry flush is bounded at 5s and must never block SIGTERM.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	pool, err := telemetry.NewPGXPool(ctx, cfg.DatabaseURL)
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
	subsidy, err := ledger.ParseID(cfg.MinistrySubsidyAccount)
	if err != nil {
		return fmt.Errorf("FERRY_TB_MINISTRY_SUBSIDY_ACCOUNT: %w", err)
	}
	platformFee, err := ledger.ParseID(cfg.PlatformFeeAccount)
	if err != nil {
		return fmt.Errorf("FERRY_TB_PLATFORM_FEE_ACCOUNT: %w", err)
	}
	ledgerService, err := ledger.New(tbClient, ledger.Topology{
		Ledger:                   cfg.TigerBeetleLedger,
		Code:                     cfg.TigerBeetleCode,
		PassengerClearingAccount: clearing,
		OperatorRevenueAccount:   revenue,
		AgentFloatAccount:        agentFloat,
		MinistrySubsidyAccount:   subsidy,
		PlatformFeeAccount:       platformFee,
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
	boarding, err := configureBoarding(cfg, ticketStore)
	if err != nil {
		return err
	}
	ticketService, err := ticketing.NewService(ticketStore, ledgerService, cfg.ManifestSalt,
		ticketing.WithVoidDualControlThreshold(cfg.VoidDualControlThresholdNGNMinor))
	if err != nil {
		return err
	}
	server, err := httpapi.NewServer(authenticator, ticketService, ticketStore, manifestStore, boarding, cfg.ManifestSalt, cfg.CompletenessKPI, logger,
		func(ctx context.Context) error { return pool.Ping(ctx) }, pipeline)
	if err != nil {
		return err
	}
	if err := configureBlueFare(ctx, cfg, pool, ticketStore, boarding, ledgerService, authenticator, server); err != nil {
		return fmt.Errorf("configure BlueFare: %w", err)
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

// configureBlueFare wires the BlueFare account-based fare system: pass
// products and passes, account-based capping, offline validation with
// rotating key epochs, the conductor store-and-forward API, top-ups and
// settlement. It fails closed on any missing dependency.
func configureBlueFare(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, ticketStore *ticketing.PostgresStore, boarding *ticketing.BoardingService, ledgerService *ledger.Service, authenticator auth.Authenticator, server *httpapi.Server) error {
	fareStore, err := fare.NewPostgresStore(pool)
	if err != nil {
		return err
	}
	passKey, err := ticketproof.LoadPrivateKeyFile(cfg.PassSigningKeyFile)
	if err != nil {
		return fmt.Errorf("load pass validation signing key: %w", err)
	}
	passSigner, err := passproof.NewSigner(passKey, cfg.PassRotationEpoch)
	if err != nil {
		return fmt.Errorf("configure pass validation signer: %w", err)
	}
	validation, err := fare.NewValidationService(fareStore, passSigner)
	if err != nil {
		return err
	}
	// Provision the rotating key directory so devices can sync it.
	if err := validation.ProvisionKeyDirectory(ctx); err != nil {
		return fmt.Errorf("provision pass validation key directory: %w", err)
	}
	passService, err := fare.NewPassService(fareStore, ledgerService, ledgerService, cfg.ManifestSalt)
	if err != nil {
		return err
	}
	journeyService, err := fare.NewJourneyService(ticketStore, fareStore, ledgerService, ledgerService, cfg.ManifestSalt)
	if err != nil {
		return err
	}
	accountService, err := fare.NewAccountService(fareStore, ledgerService, cfg.ManifestSalt, cfg.TopUpWebhookHMACSecret)
	if err != nil {
		return err
	}
	// Conductor batches verify ticket artifacts for authenticity at the scan
	// instant (the rotating window code is an online-gate-only check).
	boardingVerifier, err := ticketproofVerifier(boarding)
	if err != nil {
		return err
	}
	conductorService, err := fare.NewConductorService(fareStore, ticketStore, boardingVerifier, validation, ledgerService)
	if err != nil {
		return err
	}
	settlementService, err := fare.NewSettlementService(fareStore, ledgerService, ledgerService)
	if err != nil {
		return err
	}
	return server.RegisterFareRoutes(authenticator, httpapi.FareRoutes{
		Passes:     passService,
		Journeys:   journeyService,
		Validation: validation,
		Conductor:  conductorService,
		Accounts:   accountService,
		Settlement: settlementService,
		Store:      fareStore,
	})
}

// ticketproofVerifier exposes the boarding service's artifact verifier for
// conductor batch authenticity checks.
func ticketproofVerifier(boarding *ticketing.BoardingService) (*ticketproof.Verifier, error) {
	verifier := boarding.ArtifactVerifier()
	if verifier == nil {
		return nil, errors.New("boarding artifact verifier is unavailable (fail-closed)")
	}
	return verifier, nil
}

// configureBoarding loads the env-injected Ed25519 signing key files and
// builds the fail-closed boarding service (artifact mint/verify/embark).
func configureBoarding(cfg config.Config, store *ticketing.PostgresStore) (*ticketing.BoardingService, error) {
	current, err := ticketproof.LoadPrivateKeyFile(cfg.TicketSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load ticket signing key: %w", err)
	}
	var previous *ticketproof.RotatedKey
	if cfg.TicketPreviousSigningKeyFile != "" {
		priorKey, err := ticketproof.LoadPrivateKeyFile(cfg.TicketPreviousSigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load previous ticket signing key: %w", err)
		}
		previous = &ticketproof.RotatedKey{
			Public:     priorKey.Public().(ed25519.PublicKey),
			Epoch:      cfg.TicketRotationEpoch - 1,
			GraceUntil: cfg.TicketPreviousKeyGraceUntil,
		}
	}
	keySet, err := ticketproof.NewKeySet(current, cfg.TicketRotationEpoch, previous)
	if err != nil {
		return nil, fmt.Errorf("configure ticket signing keys: %w", err)
	}
	boarding, err := ticketing.NewBoardingService(store, keySet, cfg.TicketWindowSecret,
		ticketing.WithLegacyUnsignedEmbark(cfg.AllowLegacyUnsignedEmbark))
	if err != nil {
		return nil, fmt.Errorf("configure boarding service: %w", err)
	}
	return boarding, nil
}
