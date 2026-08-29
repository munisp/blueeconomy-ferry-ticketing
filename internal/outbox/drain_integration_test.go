//go:build integration

package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

// integrationSigner builds a throwaway provenance signer; the integration
// drain path must seal envelopes exactly like production.
func integrationSigner(t *testing.T) *provenance.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner(SigningKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestDrainAgainstLivePostgresAndKafka runs the transactional-outbox drain
// path end to end against a real PostgreSQL outbox table and a real Kafka
// broker: unpublished rows are read, enveloped, published with the idempotent
// key, marked published, and consumed back. It runs in CI
// (`.github/workflows/integration.yml`) and locally via
// `integration/compose.yaml` (see README).
// FERRY_TEST_DATABASE_URL and FERRY_TEST_KAFKA_BROKERS are required; the test
// fails closed when either is absent.
func TestDrainAgainstLivePostgresAndKafka(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	databaseURL := os.Getenv("FERRY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("FERRY_TEST_DATABASE_URL is required for integration tests")
	}
	brokerList := os.Getenv("FERRY_TEST_KAFKA_BROKERS")
	if brokerList == "" {
		t.Fatal("FERRY_TEST_KAFKA_BROKERS is required for integration tests")
	}
	brokers := strings.Split(brokerList, ",")

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	migrationDir := filepath.Clean(filepath.Join("..", "..", "db", "migrations"))
	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		t.Fatalf("list migrations: %v", err)
	}
	migrations := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			migrations = append(migrations, entry.Name())
		}
	}
	sort.Strings(migrations)
	if len(migrations) == 0 {
		t.Fatal("no migrations found")
	}
	for _, migrationFile := range migrations {
		migration, err := os.ReadFile(filepath.Clean(filepath.Join(migrationDir, migrationFile)))
		if err != nil {
			t.Fatalf("read migration %s: %v", migrationFile, err)
		}
		if _, err := pool.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", migrationFile, err)
		}
	}

	payload := json.RawMessage(`{"ticket_id":"ticket-kafka-1","principal_id":"kc-integration","ledger_post_id":"tb-post-kafka-1"}`)
	if _, err := pool.Exec(ctx,
		`INSERT INTO ferry_outbox (event_id, topic, subject_id, event_type, payload, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		"evt-kafka-1", "ferries.ticketing.v1", "ticket-kafka-1", "ferry.ticket.reserved", payload, "corr-kafka-1"); err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}

	ensureTopics(t, ctx, brokers, "ferries.ticketing.v1", "ferries.manifest.v1")

	producer, err := NewKafkaProducer(brokerList, "ferries.ticketing.v1")
	if err != nil {
		t.Fatalf("create producer: %v", err)
	}
	defer producer.Close()
	source, err := NewPostgresSource(pool)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	router := MapRouter{"ferries.ticketing.v1": producer}

	published, err := Drain(ctx, source, router, integrationSigner(t), 10)
	if err != nil {
		t.Fatalf("drain outbox: %v", err)
	}
	if published != 1 {
		t.Fatalf("published = %d, expected 1", published)
	}
	var marked bool
	if err := pool.QueryRow(ctx,
		`SELECT published_at IS NOT NULL FROM ferry_outbox WHERE event_id = 'evt-kafka-1'`).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Fatal("outbox event was not marked published")
	}

	// A second drain publishes nothing: the event is already marked.
	again, err := Drain(ctx, source, router, integrationSigner(t), 10)
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if again != 0 {
		t.Fatalf("second drain published %d events, expected 0", again)
	}

	// The consumer reads back exactly the keyed envelope the producer wrote.
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     brokers,
		Topic:       "ferries.ticketing.v1",
		GroupID:     "ferry-integration-verify",
		StartOffset: kafka.FirstOffset,
		MinBytes:    1,
		MaxBytes:    10 << 20,
		MaxWait:     10 * time.Second,
	})
	defer reader.Close()
	message, err := reader.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("read published message: %v", err)
	}
	if string(message.Key) != "evt-kafka-1" {
		t.Fatalf("kafka key = %q, expected the idempotent event key", message.Key)
	}
	var envelope Envelope
	if err := json.Unmarshal(message.Value, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.EventType != "ferries.ticketing.ticket.v1" || envelope.EventID != "evt-kafka-1" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if envelope.FHIR.ResourceType != "Bundle" || envelope.FHIR.Type != "message" || len(envelope.FHIR.Entry) != 1 {
		t.Fatalf("malformed FHIR bundle in envelope: %+v", envelope.FHIR)
	}
	if envelope.Provenance.PrincipalID != "kc-integration" || envelope.Provenance.Signature == "" {
		t.Fatalf("envelope provenance not bound: %+v", envelope.Provenance)
	}
	if envelope.CorrelationID != "corr-kafka-1" {
		t.Fatalf("correlation id = %q", envelope.CorrelationID)
	}

	// MarkPublished fails closed on a second mark for the same event.
	event := Event{EventID: "evt-kafka-1"}
	if err := source.MarkPublished(ctx, event); err == nil {
		t.Fatal("re-marking a published event was accepted")
	}
}

// ensureTopics creates the approved topics on a fresh single-broker cluster.
// Topic auto-creation races with consumer-group reads, so the test creates
// topics explicitly before publishing.
func ensureTopics(t *testing.T, ctx context.Context, brokers []string, topics ...string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		conn, err := kafka.DialContext(ctx, "tcp", brokers[0])
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		configs := make([]kafka.TopicConfig, 0, len(topics))
		for _, topic := range topics {
			configs = append(configs, kafka.TopicConfig{Topic: topic, NumPartitions: 1, ReplicationFactor: 1})
		}
		err = conn.CreateTopics(configs...)
		conn.Close()
		if err == nil {
			return
		}
		var kafkaErr kafka.Error
		if errors.As(err, &kafkaErr) && kafkaErr == kafka.TopicAlreadyExists {
			return
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	t.Fatal(fmt.Errorf("create topics on %v: %w", brokers, lastErr))
}
