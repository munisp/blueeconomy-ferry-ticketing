//go:build integration

package ticketing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	for _, migrationFile := range []string{"0001_ferry_ticketing.sql", "0002_signed_tickets.sql"} {
		migration, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "db", "migrations", migrationFile)))
		if err != nil {
			t.Fatalf("read migration %s: %v", migrationFile, err)
		}
		if _, err := pool.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", migrationFile, err)
		}
	}
	return pool
}

// TestConsumeBoardingFirstScanWinsIntegration proves the DB-enforced guard:
// two gangways consuming the same ISSUED ticket concurrently — exactly one
// UPDATE matches (boarded_at IS NULL), the other observes a duplicate.
func TestConsumeBoardingFirstScanWinsIntegration(t *testing.T) {
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx)
	defer pool.Close()

	seedTrip(t, ctx, pool, "op-int", "vessel-int", "trip-int", 2)
	if _, err := pool.Exec(ctx,
		`INSERT INTO tickets (ticket_id, trip_id, operator_id, passenger_digest_sha256, fare_ngn_minor, channel, state, purchaser_principal, correlation_id)
		 VALUES ('ticket-board-1', 'trip-int', 'op-int', $1, 250000, 'DIRECT', 'ISSUED', 'kc-integration-buyer', 'corr-int-9')`,
		"sha256:2222222222222222222222222222222222222222222222222222222222222222"); err != nil {
		t.Fatalf("insert issued ticket: %v", err)
	}

	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	const gangways = 4
	outcomes := make(chan bool, gangways)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < gangways; index++ {
		go func(gate string) {
			start.Wait()
			consumed, err := store.ConsumeBoarding(ctx, "op-int", "ticket-board-1", gate, "kid-int-1")
			if err != nil {
				t.Errorf("consume boarding: %v", err)
			}
			outcomes <- consumed
		}(fmt.Sprintf("gate-%d", index))
	}
	start.Done()
	wins := 0
	for index := 0; index < gangways; index++ {
		if <-outcomes {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("first-scan-wins violated: %d concurrent consumes succeeded", wins)
	}

	ticket, err := store.GetTicket(ctx, "ticket-board-1")
	if err != nil {
		t.Fatalf("load boarded ticket: %v", err)
	}
	if ticket.BoardedAt == nil || ticket.BoardedBy == "" || ticket.ArtifactKid != "kid-int-1" || !ticket.Embarked {
		t.Fatalf("boarding record incomplete: %+v", ticket)
	}
	// A later consume (post-race) is also rejected.
	consumed, err := store.ConsumeBoarding(ctx, "op-int", "ticket-board-1", "gate-late", "kid-int-1")
	if err != nil || consumed {
		t.Fatalf("second presentation must not consume (consumed=%v, err=%v)", consumed, err)
	}
	// Cross-operator consume never matches.
	consumed, err = store.ConsumeBoarding(ctx, "op-other", "ticket-board-1", "gate-x", "kid-int-1")
	if err != nil || consumed {
		t.Fatalf("cross-operator consume must not match (consumed=%v, err=%v)", consumed, err)
	}
}

// TestSeatReleaseOnTerminalTransitionIntegration proves the FE-4 contract
// against PostgreSQL: a terminal transition decrements seats_reserved in the
// same transaction, the release is exactly-once (the state graph and the
// optimistic-concurrency guard make a second transition fail), and the freed
// seat is purchasable again.
func TestSeatReleaseOnTerminalTransitionIntegration(t *testing.T) {
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx)
	defer pool.Close()

	seedTrip(t, ctx, pool, "op-int", "vessel-int", "trip-int", 1)
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(ticketID, key string) error {
		t.Helper()
		_, err := store.ReserveSeat(ctx, Ticket{
			TicketID: ticketID, TripID: "trip-int", OperatorID: "op-int",
			PassengerDigest: "sha256:" + ticketID + ticketID + ticketID + ticketID,
			FareNGNMinor: 250000, Channel: ChannelDirect, State: StateReserved,
			LedgerReserveID: "tb-reserve-" + ticketID,
			PurchaserPrincipal: "kc-integration-buyer", CorrelationID: "corr-" + ticketID,
		}, key, Event{
			EventID: "evt-" + ticketID, Topic: TopicTicketing, SubjectID: ticketID,
			EventType: EventTicketReserved, CorrelationID: "corr-" + ticketID,
			Payload: map[string]any{"ticket_id": ticketID},
		})
		return err
	}
	seats := func() int {
		t.Helper()
		trip, err := store.GetTrip(ctx, "trip-int")
		if err != nil {
			t.Fatal(err)
		}
		return trip.SeatsReserved
	}
	voidEvent := func(ticketID, eventID string) Event {
		return Event{
			EventID: eventID, Topic: TopicTicketing, SubjectID: ticketID,
			EventType: EventTicketVoided, CorrelationID: "corr-" + ticketID,
			Payload: map[string]any{"ticket_id": ticketID},
		}
	}

	// Capacity 1: the first reservation fills the trip, the second is refused.
	if err := reserve("ticket-sr-1", "idem-sr-1"); err != nil {
		t.Fatalf("reserve ticket-sr-1: %v", err)
	}
	if got := seats(); got != 1 {
		t.Fatalf("seats_reserved = %d, expected 1", got)
	}
	if err := reserve("ticket-sr-2", "idem-sr-2"); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("over-capacity reserve error = %v, expected ErrCapacityExceeded", err)
	}

	// Voiding releases the seat atomically with the transition.
	if _, err := store.Transition(ctx, "ticket-sr-1", 1, StateVoid, voidEvent("ticket-sr-1", "evt-sr-void")); err != nil {
		t.Fatalf("void transition: %v", err)
	}
	if got := seats(); got != 0 {
		t.Fatalf("seats_reserved after void = %d, expected 0", got)
	}
	// The release is exactly-once: a repeated terminal transition fails on the
	// version/state guard and cannot double-decrement.
	if _, err := store.Transition(ctx, "ticket-sr-1", 1, StateVoid, voidEvent("ticket-sr-1", "evt-sr-void-2")); err == nil {
		t.Fatal("second terminal transition must fail")
	}
	if _, err := store.Transition(ctx, "ticket-sr-1", 2, StateVoid, voidEvent("ticket-sr-1", "evt-sr-void-3")); err == nil {
		t.Fatal("terminal ticket must not transition again")
	}
	if got := seats(); got != 0 {
		t.Fatalf("seats_reserved after rejected retries = %d, expected 0", got)
	}

	// The freed seat is purchasable again.
	if err := reserve("ticket-sr-3", "idem-sr-3"); err != nil {
		t.Fatalf("re-purchase after release: %v", err)
	}
	if got := seats(); got != 1 {
		t.Fatalf("seats_reserved after re-purchase = %d, expected 1", got)
	}
	// REFUNDED and EXPIRED release identically.
	if _, err := store.Transition(ctx, "ticket-sr-3", 1, StateExpired, voidEvent("ticket-sr-3", "evt-sr-expire")); err != nil {
		t.Fatalf("expire transition: %v", err)
	}
	if got := seats(); got != 0 {
		t.Fatalf("seats_reserved after expiry = %d, expected 0", got)
	}
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
