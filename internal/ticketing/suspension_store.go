package ticketing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Advisory-driven departure suspensions (phase-8 met-ocean bridge). Every
// mutation is one transaction: the trip state transition, the
// trip_suspensions audit record and the passenger-notification outbox entry
// commit or roll back together.

// TripSuspension binds one departure suspension to the advisory that caused
// it (the audit record persisted in trip_suspensions).
type TripSuspension struct {
	TripID            string
	AdvisoryID        string
	Severity          string
	PhenomenonCode    string
	ZoneID            string
	EffectiveFrom     time.Time
	EffectiveUntil    time.Time
	BulletinReference string
}

// Validate fails closed on a malformed suspension record.
func (suspension TripSuspension) Validate() error {
	if suspension.TripID == "" || suspension.AdvisoryID == "" || suspension.ZoneID == "" {
		return errors.New("trip id, advisory id and zone id are required")
	}
	if suspension.Severity == "" || suspension.PhenomenonCode == "" || suspension.BulletinReference == "" {
		return errors.New("severity, phenomenon code and bulletin reference are required")
	}
	if suspension.EffectiveFrom.IsZero() || suspension.EffectiveUntil.IsZero() || !suspension.EffectiveFrom.Before(suspension.EffectiveUntil) {
		return errors.New("suspension window must be a non-empty interval")
	}
	return nil
}

// ListOpenDeparturesInWindow returns the route's open (SCHEDULED or
// BOARDING_PAUSED) departures whose scheduled departure falls inside
// [from, until], earliest first.
func (store *PostgresStore) ListOpenDeparturesInWindow(ctx context.Context, routeReference string, from, until time.Time) ([]Trip, error) {
	if routeReference == "" || from.IsZero() || until.IsZero() || !from.Before(until) {
		return nil, errors.New("route reference and a non-empty departure window are required")
	}
	rows, err := store.pool.Query(ctx,
		`SELECT trip_id, vessel_id, operator_id, route_reference, terminal_reference,
		        scheduled_departure, fare_ngn_minor, capacity, seats_reserved, status
		 FROM trips
		 WHERE route_reference = $1 AND status IN ('SCHEDULED', 'BOARDING_PAUSED')
		   AND scheduled_departure >= $2 AND scheduled_departure <= $3
		 ORDER BY scheduled_departure`, routeReference, from, until)
	if err != nil {
		return nil, fmt.Errorf("list open departures in window: %w", err)
	}
	defer rows.Close()
	trips := make([]Trip, 0)
	for rows.Next() {
		var trip Trip
		if err := rows.Scan(&trip.TripID, &trip.VesselID, &trip.OperatorID, &trip.RouteReference,
			&trip.TerminalReference, &trip.ScheduledDeparture, &trip.FareNGNMinor, &trip.Capacity,
			&trip.SeatsReserved, &trip.Status); err != nil {
			return nil, fmt.Errorf("scan open departure: %w", err)
		}
		trips = append(trips, trip)
	}
	return trips, rows.Err()
}

// SuspendDeparture transitions one open departure to SUSPENDED with the
// audit record and the passenger-notification outbox entry in one
// transaction. It reports whether the trip newly transitioned to SUSPENDED:
// a repeat of the same (trip, advisory) is an idempotent no-op, a trip
// already SUSPENDED by another advisory gains the audit record without a
// second notification, and a DEPARTED/CANCELLED trip is skipped (it can no
// longer be suspended; the advisory arrived too late for it, which the
// advisory workflow observes as "not suspended").
func (store *PostgresStore) SuspendDeparture(ctx context.Context, suspension TripSuspension, correlationID string, event Event) (bool, error) {
	if err := suspension.Validate(); err != nil {
		return false, err
	}
	if correlationID == "" {
		return false, errors.New("correlation id is required")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin suspension transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var status string
	var scheduledDeparture time.Time
	err = tx.QueryRow(ctx,
		`SELECT status, scheduled_departure FROM trips WHERE trip_id = $1 FOR UPDATE`, suspension.TripID).
		Scan(&status, &scheduledDeparture)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("lock trip for suspension: %w", err)
	}
	if status != "SCHEDULED" && status != "BOARDING_PAUSED" && status != "SUSPENDED" {
		// Departed or cancelled: nothing left to suspend. Not an error — the
		// advisory simply does not reach this trip.
		return false, nil
	}

	result, err := tx.Exec(ctx,
		`INSERT INTO trip_suspensions (trip_id, advisory_id, severity, phenomenon_code, zone_id,
		     effective_from, effective_until, bulletin_reference, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (trip_id, advisory_id) DO NOTHING`,
		suspension.TripID, suspension.AdvisoryID, suspension.Severity, suspension.PhenomenonCode,
		suspension.ZoneID, suspension.EffectiveFrom, suspension.EffectiveUntil,
		suspension.BulletinReference, correlationID)
	if err != nil {
		return false, fmt.Errorf("insert suspension audit: %w", err)
	}
	if result.RowsAffected() == 0 {
		// Same advisory replayed (at-least-once delivery): idempotent no-op.
		return false, nil
	}
	if status == "SUSPENDED" {
		// Already suspended by another advisory: the audit record now binds
		// this advisory too (resume waits for every active advisory), but the
		// state transition and notification happened on the first advisory.
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit suspension audit: %w", err)
		}
		return false, nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE trips SET status = 'SUSPENDED' WHERE trip_id = $1 AND status IN ('SCHEDULED', 'BOARDING_PAUSED')`,
		suspension.TripID); err != nil {
		return false, fmt.Errorf("suspend trip: %w", err)
	}
	if event.EventID == "" {
		return false, errors.New("suspension notification event is required")
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit suspension: %w", err)
	}
	return true, nil
}

// ResumeDeparturesForAdvisory lifts one advisory's suspensions: every
// departure it still suspends — and that no other active advisory suspends —
// returns to SCHEDULED, the audit records are marked resumed, and
// passenger-notification outbox entries are written, all in one transaction.
// It is idempotent and returns the newly resumed trip ids.
func (store *PostgresStore) ResumeDeparturesForAdvisory(ctx context.Context, advisoryID, correlationID string, eventFor func(tripID string) Event) ([]string, error) {
	if advisoryID == "" || correlationID == "" {
		return nil, errors.New("advisory id and correlation id are required")
	}
	if eventFor == nil {
		return nil, errors.New("notification event factory is required")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin resume transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT trip_id FROM trip_suspensions WHERE advisory_id = $1 AND resumed_at IS NULL
		 ORDER BY trip_id FOR UPDATE`, advisoryID)
	if err != nil {
		return nil, fmt.Errorf("list active suspensions: %w", err)
	}
	candidates := make([]string, 0)
	for rows.Next() {
		var tripID string
		if err := rows.Scan(&tripID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan active suspension: %w", err)
		}
		candidates = append(candidates, tripID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active suspensions: %w", err)
	}

	resumed := make([]string, 0, len(candidates))
	for _, tripID := range candidates {
		// A departure resumes only when no other active advisory suspends it.
		result, err := tx.Exec(ctx,
			`UPDATE trips SET status = 'SCHEDULED'
			 WHERE trip_id = $1 AND status = 'SUSPENDED'
			   AND NOT EXISTS (SELECT 1 FROM trip_suspensions other
			                   WHERE other.trip_id = $1 AND other.advisory_id <> $2
			                     AND other.resumed_at IS NULL)`,
			tripID, advisoryID)
		if err != nil {
			return nil, fmt.Errorf("resume trip %s: %w", tripID, err)
		}
		if result.RowsAffected() == 1 {
			resumed = append(resumed, tripID)
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE trip_suspensions SET resumed_at = now(), resume_correlation_id = $2
		 WHERE advisory_id = $1 AND resumed_at IS NULL`, advisoryID, correlationID); err != nil {
		return nil, fmt.Errorf("mark suspensions resumed: %w", err)
	}
	for _, tripID := range resumed {
		if err := insertEventTx(ctx, tx, eventFor(tripID)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit resume: %w", err)
	}
	return resumed, nil
}
