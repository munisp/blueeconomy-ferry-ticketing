// outbox-publisher drains the ferry transactional outbox to the
// ferries.ticketing.v1 and ferries.manifest.v1 Kafka topics with the platform
// FHIR-aligned envelope. It is at-least-once with idempotent keys and fails
// closed when Kafka or PostgreSQL is unavailable.
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/outbox"
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

	producers := make([]*outbox.KafkaProducer, 0, 2)
	router := outbox.MapRouter{}
	for _, topic := range []string{ticketing.TopicTicketing, ticketing.TopicManifest} {
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
		published, err := outbox.Drain(ctx, source, router, batch)
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
