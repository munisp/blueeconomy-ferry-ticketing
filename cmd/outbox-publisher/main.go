// outbox-publisher drains the ferry transactional outbox to the
// ferries.ticketing.v1, ferries.manifest.v1, ferries.notifications.v1 and
// ferries.fare.v1 Kafka topics with the platform FHIR-aligned envelope. It
// is at-least-once with idempotent keys and fails closed when Kafka or
// PostgreSQL is unavailable.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/fare"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/outbox"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("outbox-publisher: %v", err)
	}
}

func run() error {
	databaseURL := required("FERRY_DATABASE_URL")
	brokers := required("KAFKA_BROKERS")
	interval, err := intervalEnv("OUTBOX_POLL_INTERVAL_SECONDS")
	if err != nil {
		return err
	}
	batch, err := batchEnv("OUTBOX_BATCH_SIZE")
	if err != nil {
		return err
	}
	// Fail-closed startup: without the producer provenance key no envelope
	// may leave this service, so the process refuses to run at all.
	signer, err := provenance.LoadSignerFromEnv(outbox.SigningKeyID)
	if err != nil {
		return fmt.Errorf("load provenance signer: %w", err)
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
			log.Printf("outbox-publisher: telemetry shutdown failed: %v", err)
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

	producers := make([]*outbox.KafkaProducer, 0, 4)
	router := outbox.MapRouter{}
	for _, topic := range []string{ticketing.TopicTicketing, ticketing.TopicManifest, ticketing.TopicNotifications, fare.TopicFare} {
		producer, err := outbox.NewKafkaProducer(brokers, topic)
		if err != nil {
			return err
		}
		producers = append(producers, producer)
		router[topic] = producer
	}
	defer func() {
		for _, producer := range producers {
			_ = producer.Close()
		}
	}()
	source, err := outbox.NewPostgresSource(pool)
	if err != nil {
		return err
	}

	log.Printf("outbox-publisher: draining to ferries topics every %s (batch %d)", interval, batch)
	for {
		published, err := outbox.Drain(ctx, source, router, signer, batch)
		if err != nil {
			return fmt.Errorf("drain outbox: %w (published %d before failure)", err, published)
		}
		if published > 0 {
			log.Printf("outbox-publisher: published %d events", published)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("outbox-publisher: %s is required", name)
	}
	return value
}

func intervalEnv(name string) (time.Duration, error) {
	seconds, err := strconv.ParseInt(required(name), 10, 64)
	if err != nil || seconds <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer number of seconds", name)
	}
	return time.Duration(seconds) * time.Second, nil
}

func batchEnv(name string) (int, error) {
	batch, err := strconv.ParseInt(required(name), 10, 32)
	if err != nil || batch <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return int(batch), nil
}
