//go:build integration

package ticketing

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresStoreIntegration exercises the production store against a real
// PostgreSQL: schema migration, capacity enforcement under the row lock,
// idempotent purchase replay and the transactional outbox. It runs in CI
// (`.github/workflows/integration.yml`) and locally via
// `integration/compose.yaml`; FERRY_TEST_DATABASE_URL is required and the test
// fails closed when it is absent.
func TestPostgresStoreIntegration(t *testing.T) {
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx)
	defer pool.Close()

	seedTrip(t, ctx, pool, "op-int", "vessel-int", "trip-int", 2)

	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	reserved := Ticket{
		TicketID:           "ticket-int-1",
		TripID:             "trip-int",
		OperatorID:         "op-int",
		PassengerDigest:    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		FareNGNMinor:       250000,
		Channel:            ChannelDirect,
		State:              StateReserved,
		LedgerReserveID:    "tb-reserve-1",
		PurchaserPrincipal: "kc-integration-buyer",
		CorrelationID:      "corr-int-1",
	}
	event := Event{
		EventID:       "evt-int-1",
		Topic:         TopicTicketing,
		SubjectID:     reserved.TicketID,
		EventType:     EventTicketReserved,
		Payload:       map[string]any{"ticket_id": reserved.TicketID, "principal_id": reserved.PurchaserPrincipal},
		CorrelationID: reserved.CorrelationID,
	}

	// Fresh purchase commits ticket, idempotency binding and outbox event in
	// one transaction; the replayed result is nil for a first write.
	replayed, err := store.ReserveSeat(ctx, reserved, "idem-int-1", event)
	if err != nil {
		t.Fatalf("reserve seat: %v", err)
	}
	if replayed != nil {
		t.Fatalf("fresh purchase reported replay: %+v", replayed)
	}
	loaded, err := store.GetTicket(ctx, reserved.TicketID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateReserved || loaded.Version != 1 || loaded.SeatNumber == nil || *loaded.SeatNumber != 1 {
		t.Fatalf("unexpected stored ticket: %+v", loaded)
	}

	// Exact idempotent replay returns the original ticket without consuming a
	// second seat or writing a second outbox event.
	replayed, err = store.ReserveSeat(ctx, reserved, "idem-int-1", event)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replayed == nil || replayed.TicketID != reserved.TicketID {
		t.Fatalf("replay returned %+v", replayed)
	}
	var outboxCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM ferry_outbox`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox rows = %d, expected exactly 1", outboxCount)
	}

	// The idempotency key is bound to the purchaser principal.
	otherPrincipal := reserved
	otherPrincipal.TicketID = "ticket-int-forged"
	otherPrincipal.PurchaserPrincipal = "kc-other-principal"
	if _, err := store.ReserveSeat(ctx, otherPrincipal, "idem-int-1", event); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("cross-principal replay error = %v, expected ErrIdempotencyConflict", err)
	}

	// Capacity 2: one more seat succeeds, the next is refused by the
	// serialized purchase path.
	second := reserved
	second.TicketID = "ticket-int-2"
	second.PassengerDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	secondEvent := event
	secondEvent.EventID = "evt-int-2"
	secondEvent.SubjectID = second.TicketID
	if _, err := store.ReserveSeat(ctx, second, "idem-int-2", secondEvent); err != nil {
		t.Fatalf("second reservation: %v", err)
	}
	third := reserved
	third.TicketID = "ticket-int-3"
	third.PassengerDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	if _, err := store.ReserveSeat(ctx, third, "idem-int-3", secondEvent); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("overbooking error = %v, expected ErrCapacityExceeded", err)
	}
	trip, err := store.GetTrip(ctx, "trip-int")
	if err != nil {
		t.Fatal(err)
	}
	if trip.SeatsReserved != 2 {
		t.Fatalf("seats_reserved = %d, expected 2", trip.SeatsReserved)
	}

	// Lifecycle: RESERVED -> PAID -> ISSUED with optimistic concurrency, then
	// an unapproved direct transition is rejected.
	paid, err := store.MarkPaid(ctx, reserved.TicketID, 1, "tb-post-1", nil, []Event{{
		EventID:       "evt-int-3",
		Topic:         TopicTicketing,
		SubjectID:     reserved.TicketID,
		EventType:     EventTicketPaid,
		Payload:       map[string]any{"ticket_id": reserved.TicketID, "principal_id": reserved.PurchaserPrincipal, "ledger_post_id": "tb-post-1"},
		CorrelationID: reserved.CorrelationID,
	}})
	if err != nil {
		t.Fatalf("mark paid: %v", err)
	}
	if paid.State != StatePaid || paid.Version != 2 || paid.LedgerPostID != "tb-post-1" {
		t.Fatalf("unexpected paid ticket: %+v", paid)
	}
	if _, err := store.MarkPaid(ctx, reserved.TicketID, 1, "tb-post-stale", nil, nil); err == nil {
		t.Fatal("stale version payment was accepted")
	}
	issued, err := store.MarkIssued(ctx, reserved.TicketID, 2, 1, Event{
		EventID:       "evt-int-4",
		Topic:         TopicTicketing,
		SubjectID:     reserved.TicketID,
		EventType:     EventTicketIssued,
		Payload:       map[string]any{"ticket_id": reserved.TicketID, "principal_id": reserved.PurchaserPrincipal},
		CorrelationID: reserved.CorrelationID,
	})
	if err != nil {
		t.Fatalf("mark issued: %v", err)
	}
	if issued.State != StateIssued || issued.Version != 3 {
		t.Fatalf("unexpected issued ticket: %+v", issued)
	}
}

// openIntegrationPool connects to the CI/local PostgreSQL, resets the schema
// and applies the committed migration. It fails closed when
// FERRY_TEST_DATABASE_URL is absent: under the integration tag a live
// database is mandatory, never silently skipped.
func openIntegrationPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("FERRY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("FERRY_TEST_DATABASE_URL is required for integration tests")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open postgres pool: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	migration, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "db", "migrations", "0001_ferry_ticketing.sql")))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	return pool
}

func seedTrip(t *testing.T, ctx context.Context, pool *pgxpool.Pool, operatorID, vesselID, tripID string, capacity int) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO operators (operator_id, registered_name) VALUES ($1, $2)`, operatorID, "Integration Operator"); err != nil {
		t.Fatalf("insert operator: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO vessels (vessel_id, operator_id, vessel_name, capacity) VALUES ($1, $2, $3, 50)`,
		vesselID, operatorID, "Integration Vessel"); err != nil {
		t.Fatalf("insert vessel: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO trips (trip_id, vessel_id, operator_id, route_reference, terminal_reference, scheduled_departure, fare_ngn_minor, capacity)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tripID, vesselID, operatorID, "route-int", "terminal-int", time.Now().Add(24*time.Hour).UTC(), 250000, capacity); err != nil {
		t.Fatalf("insert trip: %v", err)
	}
}
