package manifest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// PostgresStore implements TripTicketsSource against PostgreSQL. All queries
// are parameterized.
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

// ManifestTickets implements TripTicketsSource.
func (store *PostgresStore) ManifestTickets(ctx context.Context, tripID string) ([]ticketing.Ticket, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT ticket_id, trip_id, operator_id, passenger_digest_sha256, fare_ngn_minor, channel, state,
		        version, seat_number, correlation_id, embarked
		 FROM tickets WHERE trip_id = $1 AND state IN ('PAID', 'ISSUED') ORDER BY seat_number`, tripID)
	if err != nil {
		return nil, fmt.Errorf("list manifest tickets: %w", err)
	}
	defer rows.Close()
	tickets := make([]ticketing.Ticket, 0)
	for rows.Next() {
		var ticket ticketing.Ticket
		var seatNumber *int
		if err := rows.Scan(&ticket.TicketID, &ticket.TripID, &ticket.OperatorID, &ticket.PassengerDigest,
			&ticket.FareNGNMinor, &ticket.Channel, &ticket.State, &ticket.Version, &seatNumber,
			&ticket.CorrelationID, &ticket.Embarked); err != nil {
			return nil, fmt.Errorf("scan manifest ticket: %w", err)
		}
		ticket.SeatNumber = seatNumber
		tickets = append(tickets, ticket)
	}
	return tickets, rows.Err()
}

// RecordManifest implements TripTicketsSource: manifest row and outbox event
// commit atomically.
func (store *PostgresStore) RecordManifest(ctx context.Context, manifest Manifest, event ticketing.Event) error {
	if manifest.ManifestID == "" || manifest.TripID == "" || manifest.DigestSHA256 == "" {
		return errors.New("manifest id, trip id and digest are required")
	}
	if manifest.PassengerCount < 0 || manifest.ExpectedPassengers < 0 {
		return errors.New("manifest passenger counts must be non-negative")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin manifest transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO manifests (manifest_id, trip_id, operator_id, vessel_reference, terminal_reference,
		     scheduled_departure, passenger_count, expected_passengers, manifest_digest_sha256, exported_by_principal)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		manifest.ManifestID, manifest.TripID, manifest.OperatorID, manifest.VesselReference,
		manifest.TerminalReference, manifest.ScheduledDeparture, manifest.PassengerCount,
		manifest.ExpectedPassengers, manifest.DigestSHA256, manifest.ExportedByPrincipal); err != nil {
		return fmt.Errorf("insert manifest: %w", err)
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("encode manifest event payload: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO ferry_outbox (event_id, topic, subject_id, event_type, payload, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		event.EventID, event.Topic, event.SubjectID, event.EventType, payload, event.CorrelationID); err != nil {
		return fmt.Errorf("insert manifest outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit manifest: %w", err)
	}
	return nil
}

// ManifestCompleteness implements TripTicketsSource: total manifested vs
// expected passengers across the operator's exported manifests.
func (store *PostgresStore) ManifestCompleteness(ctx context.Context, operatorID string) (int64, int64, error) {
	var included, expected int64
	err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(passenger_count), 0), COALESCE(SUM(expected_passengers), 0)
		 FROM manifests WHERE operator_id = $1`, operatorID).Scan(&included, &expected)
	if err != nil {
		return 0, 0, fmt.Errorf("aggregate manifest completeness: %w", err)
	}
	return included, expected, nil
}

// LatestManifest returns the most recent export for a trip.
func (store *PostgresStore) LatestManifest(ctx context.Context, tripID string) (Manifest, error) {
	var manifest Manifest
	err := store.pool.QueryRow(ctx,
		`SELECT manifest_id, trip_id, operator_id, vessel_reference, terminal_reference, scheduled_departure,
		        passenger_count, expected_passengers, manifest_digest_sha256, exported_by_principal, exported_at
		 FROM manifests WHERE trip_id = $1 ORDER BY exported_at DESC LIMIT 1`, tripID).
		Scan(&manifest.ManifestID, &manifest.TripID, &manifest.OperatorID, &manifest.VesselReference,
			&manifest.TerminalReference, &manifest.ScheduledDeparture, &manifest.PassengerCount,
			&manifest.ExpectedPassengers, &manifest.DigestSHA256, &manifest.ExportedByPrincipal, &manifest.ExportedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Manifest{}, ticketing.ErrNotFound
		}
		return Manifest{}, fmt.Errorf("load manifest: %w", err)
	}
	return manifest, nil
}
