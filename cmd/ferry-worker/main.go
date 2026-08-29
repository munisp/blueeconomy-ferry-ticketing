// ferry-worker runs the Temporal worker hosting FerryTicketWorkflow. It is
// environment-configured and fails closed when Temporal or PostgreSQL is
// unavailable.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
	temporalotel "go.temporal.io/sdk/contrib/opentelemetry"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/interceptor"
	"go.temporal.io/sdk/worker"
	sdkworkflow "go.temporal.io/sdk/workflow"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/fare"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	ferryworkflow "github.com/munisp/blueeconomy-ferry-ticketing/internal/workflow"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("ferry-worker failed", "error", err.Error())
		os.Exit(1)
	}
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func requiredUint32(name string) (uint32, error) {
	value, err := required(name)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a non-zero uint32", name)
	}
	return uint32(parsed), nil
}

// optionalInt reads an integer env var with a default.
func optionalInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

// optionalDurationSeconds reads a seconds-valued env var with a default.
func optionalDurationSeconds(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a positive number of seconds", name)
	}
	return time.Duration(parsed) * time.Second, nil
}

func run(logger *slog.Logger) error {
	databaseURL, err := required("FERRY_DATABASE_URL")
	if err != nil {
		return err
	}
	temporalAddress, err := required("TEMPORAL_ADDRESS")
	if err != nil {
		return err
	}
	temporalNamespace, err := required("TEMPORAL_NAMESPACE")
	if err != nil {
		return err
	}
	taskQueue, err := required("TEMPORAL_TASK_QUEUE")
	if err != nil {
		return err
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

	pool, err := telemetry.NewPGXPool(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	store, err := ticketing.NewPostgresStore(pool)
	if err != nil {
		return err
	}

	// Purchase-saga reconciler: resolves aged RESERVED tickets against the
	// TigerBeetle reserve state so a posted charge always reaches PAID/ISSUED
	// and an auto-voided reserve always reaches EXPIRED (releasing the seat).
	reconciler, err := configureReconciler(store)
	if err != nil {
		return err
	}
	defer reconciler.close()
	go reconciler.run(ctx, logger)

	// Nightly pass expiry sweep (ACTIVE -> EXPIRED past valid_to). Cap
	// accumulator rollover is lazy by design, so this is the only fare sweep.
	go runPassExpirySweep(ctx, pool, logger)

	// Temporal OTel interceptors: workflow/activity spans join the service
	// trace and inbound workflow calls extract the caller's context
	// (OTEL_DESIGN §3 Temporal row). With telemetry disabled the interceptor
	// spans are no-ops.
	tracingInterceptor, err := temporalotel.NewTracingInterceptor(temporalotel.TracerOptions{})
	if err != nil {
		return fmt.Errorf("build temporal tracing interceptor: %w", err)
	}
	temporalClient, err := client.Dial(client.Options{
		HostPort:     temporalAddress,
		Namespace:    temporalNamespace,
		Logger:       logger,
		Interceptors: []interceptor.ClientInterceptor{tracingInterceptor},
	})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer temporalClient.Close()

	activities := &ferryworkflow.Activities{
		PauseBoarding: func(ctx context.Context, tripID string) error {
			return store.MarkTripBoardingPaused(ctx, tripID)
		},
		MarkTripDeparted: func(ctx context.Context, tripID string) error {
			return store.MarkTripDeparted(ctx, tripID)
		},
		EmitWeatherAlert: func(ctx context.Context, tripID, routeReference string, alert ferryworkflow.AdverseWeatherSignal, correlationID string) error {
			return store.AppendEvent(ctx, ticketing.Event{
				EventID:       uuid.NewString(),
				Topic:         ticketing.TopicManifest,
				SubjectID:     tripID,
				EventType:     ticketing.EventAdverseWeather,
				CorrelationID: correlationID,
				Payload: map[string]any{
					"alert_id":           alert.AlertID,
					"trip_id":            tripID,
					"route_reference":    routeReference,
					"severity":           alert.Severity,
					"phenomenon_code":    alert.PhenomenonCode,
					"effective_from":     alert.EffectiveFrom,
					"effective_until":    alert.EffectiveUntil,
					"bulletin_reference": alert.BulletinReference,
				},
			})
		},
		RecordManifestIncomplete: func(ctx context.Context, tripID, correlationID string) error {
			return store.AppendEvent(ctx, ticketing.Event{
				EventID:       uuid.NewString(),
				Topic:         ticketing.TopicManifest,
				SubjectID:     tripID,
				EventType:     ticketing.EventManifestIncomplete,
				CorrelationID: correlationID,
				Payload: map[string]any{
					"trip_id": tripID,
				},
			})
		},
	}
	definition, err := ferryworkflow.NewFerryWorkflow(activities)
	if err != nil {
		return err
	}

	temporalWorker := worker.New(temporalClient, taskQueue, worker.Options{
		Interceptors: []interceptor.WorkerInterceptor{tracingInterceptor},
	})
	temporalWorker.RegisterWorkflowWithOptions(definition.FerryTicketWorkflow, sdkworkflow.RegisterOptions{Name: "FerryTicketWorkflow"})
	temporalWorker.RegisterActivityWithOptions(activities.PauseBoarding, activity.RegisterOptions{Name: ferryworkflow.ActivityPauseBoarding})
	temporalWorker.RegisterActivityWithOptions(activities.MarkTripDeparted, activity.RegisterOptions{Name: ferryworkflow.ActivityMarkTripDeparted})
	temporalWorker.RegisterActivityWithOptions(activities.EmitWeatherAlert, activity.RegisterOptions{Name: ferryworkflow.ActivityEmitWeatherAlert})
	temporalWorker.RegisterActivityWithOptions(activities.RecordManifestIncomplete, activity.RegisterOptions{Name: ferryworkflow.ActivityRecordManifestIncomplete})

	logger.Info("ferry-worker starting", "task_queue", taskQueue, "namespace", temporalNamespace)
	errCh := make(chan error, 1)
	go func() { errCh <- temporalWorker.Run(worker.InterruptCh()) }()
	select {
	case <-ctx.Done():
		temporalWorker.Stop()
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("run temporal worker: %w", err)
		}
		return nil
	}
}

// reconciler bundles the purchase-saga recovery sweep dependencies.
type reconciler struct {
	service       *ticketing.Service
	ledgerClient  tigerbeetle.Client
	interval      time.Duration
	completionAge time.Duration
	expiryAge     time.Duration
	batch         int
}

func (reconciler *reconciler) close() {
	reconciler.ledgerClient.Close()
}

// run sweeps on a ticker until the process shuts down. Sweep failures are
// logged and retried on the next tick: every recovery step is
// idempotent-safe, so a partial sweep never strands state.
func (reconciler *reconciler) run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(reconciler.interval)
	defer ticker.Stop()
	logger.Info("purchase-saga reconciler starting",
		"interval", reconciler.interval.String(),
		"completion_age", reconciler.completionAge.String(),
		"expiry_age", reconciler.expiryAge.String(),
		"batch", reconciler.batch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := reconciler.service.Reconcile(ctx, reconciler.completionAge, reconciler.expiryAge, reconciler.batch)
			if err != nil {
				logger.Error("reconciler sweep failed", "error", err.Error())
				continue
			}
			if report.Completed > 0 || report.Expired > 0 || report.Failed > 0 {
				logger.Info("reconciler sweep",
					"completed", report.Completed, "expired", report.Expired,
					"pending", report.Pending, "failed", report.Failed)
			}
		}
	}
}

// runPassExpirySweep expires ACTIVE passes past valid_to on a configurable
// cadence (default nightly), following the reconciler's loop pattern.
func runPassExpirySweep(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	interval, err := optionalDurationSeconds("FERRY_PASS_SWEEP_INTERVAL_SECONDS", 24*time.Hour)
	if err != nil {
		logger.Error("pass expiry sweep disabled", "error", err)
		return
	}
	batchSize, err := optionalInt("FERRY_PASS_SWEEP_BATCH", 500)
	if err != nil {
		logger.Error("pass expiry sweep disabled", "error", err)
		return
	}
	fareStore, err := fare.NewPostgresStore(pool)
	if err != nil {
		logger.Error("pass expiry sweep disabled", "error", err)
		return
	}
	logger.Info("pass expiry sweep armed", "interval", interval, "batch", batchSize)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			swept, err := fare.SweepExpiredPasses(ctx, fareStore, time.Now().UTC(), batchSize)
			if err != nil {
				logger.Error("pass expiry sweep failed", "error", err)
				continue
			}
			if swept > 0 {
				logger.Info("pass expiry sweep completed", "expired", swept)
			}
		}
	}
}

// configureReconciler loads the TigerBeetle topology and sweep cadence from
// the environment. The ledger is fail-closed: the worker refuses to start
// without it, mirroring ferry-api. FERRY_SWEEP_INTERVAL_SECONDS (default 60)
// and FERRY_SWEEP_COMPLETION_AGE_SECONDS (default 60) tune the cadence; the
// expiry age is the ledger pending timeout plus a fixed 30-second grace so a
// reservation is only expired after TigerBeetle has auto-voided its reserve.
func configureReconciler(store *ticketing.PostgresStore) (*reconciler, error) {
	address, err := required("FERRY_TB_ADDRESS")
	if err != nil {
		return nil, err
	}
	clusterID, err := requiredUint32("FERRY_TB_CLUSTER_ID")
	if err != nil {
		return nil, err
	}
	ledgerID, err := requiredUint32("FERRY_TB_LEDGER")
	if err != nil {
		return nil, err
	}
	code, err := requiredUint32("FERRY_TB_CODE")
	if err != nil {
		return nil, err
	}
	if code > 65535 {
		return nil, errors.New("FERRY_TB_CODE must fit a uint16")
	}
	clearing, err := required("FERRY_TB_PASSENGER_CLEARING_ACCOUNT")
	if err != nil {
		return nil, err
	}
	revenue, err := required("FERRY_TB_OPERATOR_REVENUE_ACCOUNT")
	if err != nil {
		return nil, err
	}
	agentFloat, err := required("FERRY_TB_AGENT_FLOAT_ACCOUNT")
	if err != nil {
		return nil, err
	}
	pendingTimeout, err := requiredUint32("FERRY_TB_PENDING_TIMEOUT_SECONDS")
	if err != nil {
		return nil, err
	}
	manifestSalt, err := required("FERRY_MANIFEST_SALT")
	if err != nil {
		return nil, err
	}

	clearingID, err := ledger.ParseID(clearing)
	if err != nil {
		return nil, fmt.Errorf("FERRY_TB_PASSENGER_CLEARING_ACCOUNT: %w", err)
	}
	revenueID, err := ledger.ParseID(revenue)
	if err != nil {
		return nil, fmt.Errorf("FERRY_TB_OPERATOR_REVENUE_ACCOUNT: %w", err)
	}
	agentFloatID, err := ledger.ParseID(agentFloat)
	if err != nil {
		return nil, fmt.Errorf("FERRY_TB_AGENT_FLOAT_ACCOUNT: %w", err)
	}
	tbClient, err := tigerbeetle.NewClient(tigerbeetle.ToUint128(uint64(clusterID)), []string{address})
	if err != nil {
		return nil, fmt.Errorf("connect TigerBeetle: %w", err)
	}
	ledgerService, err := ledger.New(tbClient, ledger.Topology{
		Ledger:                   ledgerID,
		Code:                     uint16(code),
		PassengerClearingAccount: clearingID,
		OperatorRevenueAccount:   revenueID,
		AgentFloatAccount:        agentFloatID,
		PendingTimeoutSeconds:    pendingTimeout,
	})
	if err != nil {
		tbClient.Close()
		return nil, fmt.Errorf("configure ledger: %w", err)
	}
	ticketService, err := ticketing.NewService(store, ledgerService, manifestSalt)
	if err != nil {
		tbClient.Close()
		return nil, err
	}
	interval, err := optionalDurationSeconds("FERRY_SWEEP_INTERVAL_SECONDS", 60*time.Second)
	if err != nil {
		tbClient.Close()
		return nil, err
	}
	completionAge, err := optionalDurationSeconds("FERRY_SWEEP_COMPLETION_AGE_SECONDS", 60*time.Second)
	if err != nil {
		tbClient.Close()
		return nil, err
	}
	return &reconciler{
		service:       ticketService,
		ledgerClient:  tbClient,
		interval:      interval,
		completionAge: completionAge,
		expiryAge:     time.Duration(pendingTimeout)*time.Second + 30*time.Second,
		batch:         100,
	}, nil
}
