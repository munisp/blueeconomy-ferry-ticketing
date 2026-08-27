package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production Store. Capacity is enforced inside the
// purchase transaction (trip row locked FOR UPDATE + seats_reserved CHECK),
// and every mutation writes its outbox events in the same transaction.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore fails closed on a nil pool.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	return &PostgresStore{pool: pool}, nil
}

// ReserveSeat implements Store.
func (store *PostgresStore) ReserveSeat(ctx context.Context, ticket Ticket, idempotencyKey string, event Event) (*Ticket, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return nil, fmt.Errorf("begin purchase transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Idempotent replay: the key is globally unique and principal-bound.
	var (
		boundTicketID  string
		boundPrincipal string
	)
	lookupErr := tx.QueryRow(ctx,
		`SELECT ticket_id, purchaser_principal FROM purchase_idempotency WHERE idempotency_key = $1`,
		idempotencyKey).Scan(&boundTicketID, &boundPrincipal)
	if lookupErr == nil {
		if boundPrincipal != ticket.PurchaserPrincipal {
			return nil, ErrIdempotencyConflict
		}
		replayed, err := getTicketTx(ctx, tx, boundTicketID)
		if err != nil {
			return nil, fmt.Errorf("load idempotent ticket: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit idempotent replay: %w", err)
		}
		return &replayed, nil
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) {
		return nil, fmt.Errorf("lookup idempotency key: %w", lookupErr)
	}

	// Capacity enforcement under the row lock; the CHECK constraint is the
	// final backstop so overbooking is impossible under any interleaving.
	var seatsReserved, capacity int
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT seats_reserved, capacity, status FROM trips WHERE trip_id = $1 FOR UPDATE`,
		ticket.TripID).Scan(&seatsReserved, &capacity, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lock trip for purchase: %w", err)
	}
	if status != "SCHEDULED" {
		return nil, fmt.Errorf("trip is not open for purchase (status %s)", status)
	}
	if seatsReserved >= capacity {
		return nil, ErrCapacityExceeded
	}
	seatNumber := seatsReserved + 1
	ticket.SeatNumber = &seatNumber

	if _, err := tx.Exec(ctx,
		`UPDATE trips SET seats_reserved = seats_reserved + 1 WHERE trip_id = $1 AND seats_reserved < $2`,
		ticket.TripID, capacity); err != nil {
		return nil, fmt.Errorf("increment reserved seats: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tickets (ticket_id, trip_id, operator_id, passenger_digest_sha256, fare_ngn_minor,
		     channel, state, version, seat_number, agent_id, ledger_reserve_id, purchaser_principal, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, NULLIF($9, ''), $10, $11, $12)`,
		ticket.TicketID, ticket.TripID, ticket.OperatorID, ticket.PassengerDigest, ticket.FareNGNMinor,
		string(ticket.Channel), string(ticket.State), seatNumber, ticket.AgentID, ticket.LedgerReserveID,
		ticket.PurchaserPrincipal, ticket.CorrelationID); err != nil {
		return nil, fmt.Errorf("insert ticket: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO purchase_idempotency (idempotency_key, purchaser_principal, ticket_id) VALUES ($1, $2, $3)`,
		idempotencyKey, ticket.PurchaserPrincipal, ticket.TicketID); err != nil {
		return nil, fmt.Errorf("bind idempotency key: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit purchase: %w", err)
	}
	return nil, nil
}

// GetTicket implements Store.
func (store *PostgresStore) GetTicket(ctx context.Context, ticketID string) (Ticket, error) {
	return getTicketTx(ctx, store.pool, ticketID)
}

func getTicketTx(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, ticketID string) (Ticket, error) {
	var ticket Ticket
	var seatNumber *int
	var agentID, reserveID, postID *string
	err := querier.QueryRow(ctx,
		`SELECT ticket_id, trip_id, operator_id, passenger_digest_sha256, fare_ngn_minor, channel, state,
		        version, seat_number, agent_id, ledger_reserve_id, ledger_post_id, purchaser_principal,
		        correlation_id, embarked, created_at, updated_at
		 FROM tickets WHERE ticket_id = $1`, ticketID).
		Scan(&ticket.TicketID, &ticket.TripID, &ticket.OperatorID, &ticket.PassengerDigest, &ticket.FareNGNMinor,
			&ticket.Channel, &ticket.State, &ticket.Version, &seatNumber, &agentID, &reserveID, &postID,
			&ticket.PurchaserPrincipal, &ticket.CorrelationID, &ticket.Embarked, &ticket.CreatedAt, &ticket.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Ticket{}, ErrNotFound
		}
		return Ticket{}, fmt.Errorf("load ticket: %w", err)
	}
	ticket.SeatNumber = seatNumber
	if agentID != nil {
		ticket.AgentID = *agentID
	}
	if reserveID != nil {
		ticket.LedgerReserveID = *reserveID
	}
	if postID != nil {
		ticket.LedgerPostID = *postID
	}
	return ticket, nil
}

// MarkPaid implements Store.
func (store *PostgresStore) MarkPaid(ctx context.Context, ticketID string, version int64, ledgerPostID string, cashIn *CashIn, events []Event) (Ticket, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("begin payment transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	ticket, err := transitionTx(ctx, tx, ticketID, version, StatePaid)
	if err != nil {
		return Ticket{}, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tickets SET ledger_post_id = $2 WHERE ticket_id = $1`, ticketID, ledgerPostID); err != nil {
		return Ticket{}, fmt.Errorf("record ledger post: %w", err)
	}
	if cashIn != nil {
		if _, err := tx.Exec(ctx,
			`INSERT INTO cash_in_events (cash_in_id, ticket_id, agent_id, amount_ngn_minor, ledger_transfer_id)
			 VALUES ($1, $2, $3, $4, $5)`,
			cashIn.CashInID, ticketID, cashIn.AgentID, cashIn.AmountNGNMinor, cashIn.LedgerTransferID); err != nil {
			return Ticket{}, fmt.Errorf("record cash-in ledger event: %w", err)
		}
	}
	for _, event := range events {
		if err := insertEventTx(ctx, tx, event); err != nil {
			return Ticket{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("commit payment: %w", err)
	}
	ticket.LedgerPostID = ledgerPostID
	return ticket, nil
}

// MarkIssued implements Store.
func (store *PostgresStore) MarkIssued(ctx context.Context, ticketID string, version int64, seatNumber int, event Event) (Ticket, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("begin issue transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	ticket, err := transitionTx(ctx, tx, ticketID, version, StateIssued)
	if err != nil {
		return Ticket{}, err
	}
	if seatNumber > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE tickets SET seat_number = $2 WHERE ticket_id = $1`, ticketID, seatNumber); err != nil {
			return Ticket{}, fmt.Errorf("assign seat: %w", err)
		}
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return Ticket{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("commit issue: %w", err)
	}
	return ticket, nil
}

// Transition implements Store.
func (store *PostgresStore) Transition(ctx context.Context, ticketID string, version int64, to State, event Event) (Ticket, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Ticket{}, fmt.Errorf("begin transition transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	ticket, err := transitionTx(ctx, tx, ticketID, version, to)
	if err != nil {
		return Ticket{}, err
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return Ticket{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Ticket{}, fmt.Errorf("commit transition: %w", err)
	}
	return ticket, nil
}

// transitionTx applies an approved state move with optimistic concurrency
// inside an open transaction.
func transitionTx(ctx context.Context, tx pgx.Tx, ticketID string, version int64, to State) (Ticket, error) {
	if !to.Terminal() && to != StatePaid && to != StateIssued {
		return Ticket{}, fmt.Errorf("%w: target state %s", ErrInvalidTransition, to)
	}
	ticket, err := getTicketTx(ctx, tx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if ticket.Version != version {
		return Ticket{}, fmt.Errorf("ticket version conflict: stored %d, requested %d", ticket.Version, version)
	}
	if !ValidTransition(ticket.State, to) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, to)
	}
	result, err := tx.Exec(ctx,
		`UPDATE tickets SET state = $2, version = version + 1, updated_at = now()
		 WHERE ticket_id = $1 AND version = $3`, ticketID, string(to), version)
	if err != nil {
		return Ticket{}, fmt.Errorf("transition ticket: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Ticket{}, fmt.Errorf("ticket version conflict on update for %s", ticketID)
	}
	ticket.State = to
	ticket.Version = version + 1
	return ticket, nil
}

// GetTrip implements Store.
func (store *PostgresStore) GetTrip(ctx context.Context, tripID string) (Trip, error) {
	return getTripQuerier(ctx, store.pool, tripID)
}

func getTripQuerier(ctx context.Context, querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tripID string) (Trip, error) {
	var trip Trip
	err := querier.QueryRow(ctx,
		`SELECT trip_id, vessel_id, operator_id, route_reference, terminal_reference,
		        scheduled_departure, fare_ngn_minor, capacity, seats_reserved, status
		 FROM trips WHERE trip_id = $1`, tripID).
		Scan(&trip.TripID, &trip.VesselID, &trip.OperatorID, &trip.RouteReference, &trip.TerminalReference,
			&trip.ScheduledDeparture, &trip.FareNGNMinor, &trip.Capacity, &trip.SeatsReserved, &trip.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Trip{}, ErrNotFound
		}
		return Trip{}, fmt.Errorf("load trip: %w", err)
	}
	return trip, nil
}

// insertEventTx writes one outbox event inside the domain transaction.
func insertEventTx(ctx context.Context, tx pgx.Tx, event Event) error {
	if event.EventID == "" || event.Topic == "" || event.EventType == "" || event.SubjectID == "" || event.CorrelationID == "" {
		return errors.New("outbox event identifiers are required")
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO ferry_outbox (event_id, topic, subject_id, event_type, payload, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		event.EventID, event.Topic, event.SubjectID, event.EventType, payload, event.CorrelationID); err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}
