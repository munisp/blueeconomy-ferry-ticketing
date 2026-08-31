// metocean-bridge consumes signed met-ocean advisories from Kafka and drives
// per-route Temporal workflows that suspend and resume affected ferry
// departures. It is environment-configured and fails closed: no key
// directory, no transport security, no zone mapping and no dead-letter topic
// are all startup errors, and no envelope is ever processed without a valid
// fleet provenance signature.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.temporal.io/sdk/client"
	otelcontrib "go.temporal.io/sdk/contrib/opentelemetry"
	"go.temporal.io/sdk/interceptor"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/metocean"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("metocean-bridge failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := metocean.LoadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	telemetryConfig, err := telemetry.LoadConfig("metocean-bridge")
	if err != nil {
		return err
	}
	telemetryPipeline, err := telemetry.Setup(ctx, telemetryConfig)
	if err != nil {
		return fmt.Errorf("setup telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetryPipeline.Shutdown(shutdownCtx)
	}()

	// Provenance verification is mandatory: the key directory must load or
	// the bridge refuses to start.
	directory, err := provenance.LoadDirectory(config.KeyDirectoryPath)
	if err != nil {
		return fmt.Errorf("load provenance key directory: %w", err)
	}
	logger.Info("provenance key directory loaded", "kids", strings.Join(directory.KeyIDs(), ","))

	metrics, err := metocean.NewMetrics(telemetryPipeline.Meter())
	if err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}

	source, err := metocean.NewKafkaMessageSource(config)
	if err != nil {
		return fmt.Errorf("configure Kafka consumer: %w", err)
	}
	defer source.Close()
	dlq, err := metocean.NewKafkaSink(config)
	if err != nil {
		return fmt.Errorf("configure Kafka dead-letter sink: %w", err)
	}
	defer dlq.Close()

	tracingInterceptor, err := otelcontrib.NewTracingInterceptor(otelcontrib.TracerOptions{Tracer: telemetryPipeline.Tracer()})
	if err != nil {
		return fmt.Errorf("build temporal tracing interceptor: %w", err)
	}
	temporalClient, err := client.Dial(client.Options{
		HostPort:     config.TemporalAddress,
		Namespace:    config.TemporalNamespace,
		Logger:       logger,
		Interceptors: []interceptor.ClientInterceptor{tracingInterceptor},
	})
	if err != nil {
		return fmt.Errorf("dial temporal: %w", err)
	}
	defer temporalClient.Close()

	bridge, err := metocean.NewBridge(temporalClient, config, metrics, logger)
	if err != nil {
		return err
	}
	consumer, err := metocean.NewConsumer(source, dlq, bridge, directory, config.KafkaTopic, telemetryPipeline.Tracer(), metrics, logger)
	if err != nil {
		return err
	}

	// Optional local Prometheus endpoint for the bridge counters.
	if address := strings.TrimSpace(os.Getenv("MET_OCEAN_METRICS_ADDRESS")); address != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", telemetryPipeline.MetricsHandler())
		server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				logger.Error("metrics server failed", "error", serveErr.Error())
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		logger.Info("metrics endpoint serving", "address", address)
	}

	logger.Info("metocean-bridge starting",
		"topic", config.KafkaTopic, "group", config.KafkaGroupID,
		"dlq", config.KafkaDLQTopic, "task_queue", config.TemporalTaskQueue,
		"tracing", telemetryPipeline.Enabled())
	return consumer.Run(ctx)
}
