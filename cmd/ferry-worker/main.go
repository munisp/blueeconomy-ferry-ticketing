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
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	sdkworkflow "go.temporal.io/sdk/workflow"

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

	pool, err := pgxpool.New(ctx, databaseURL)
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

	temporalClient, err := client.Dial(client.Options{
		HostPort:  temporalAddress,
		Namespace: temporalNamespace,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer temporalClient.Close()

	activities := &ferryworkflow.Activities{
		PauseBoarding: func(ctx context.Context, tripID string) error {
			return store.MarkTripBoardingPaused(ctx, tripID)
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

	temporalWorker := worker.New(temporalClient, taskQueue, worker.Options{})
	temporalWorker.RegisterWorkflowWithOptions(definition.FerryTicketWorkflow, sdkworkflow.RegisterOptions{Name: "FerryTicketWorkflow"})
	temporalWorker.RegisterActivityWithOptions(activities.PauseBoarding, activity.RegisterOptions{Name: ferryworkflow.ActivityPauseBoarding})
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
