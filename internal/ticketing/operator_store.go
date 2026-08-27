package ticketing

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Operator-scoped persistence. Every query filters by operator_id so the
// service layer enforces tenancy at the database, not only at the edge.

// CreateVessel registers one vessel for the operator.
func (store *PostgresStore) CreateVessel(ctx context.Context, vessel Vessel) error {
	if vessel.VesselID == "" || vessel.OperatorID == "" || vessel.Name == "" || vessel.Capacity <= 0 {
		return errors.New("vessel id, operator id, name and positive capacity are required")
	}
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO vessels (vessel_id, operator_id, vessel_name, imo_number, capacity, active)
		 VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)`,
		vessel.VesselID, vessel.OperatorID, vessel.Name, vessel.IMONumber, vessel.Capacity, vessel.Active); err != nil {
		return fmt.Errorf("insert vessel: %w", err)
	}
	return nil
}

// ListVessels returns the operator's vessels.
func (store *PostgresStore) ListVessels(ctx context.Context, operatorID string) ([]Vessel, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT vessel_id, operator_id, vessel_name, COALESCE(imo_number, ''), capacity, active
		 FROM vessels WHERE operator_id = $1 ORDER BY created_at`, operatorID)
	if err != nil {
		return nil, fmt.Errorf("list vessels: %w", err)
	}
	defer rows.Close()
	vessels := make([]Vessel, 0)
	for rows.Next() {
		var vessel Vessel
		if err := rows.Scan(&vessel.VesselID, &vessel.OperatorID, &vessel.Name, &vessel.IMONumber, &vessel.Capacity, &vessel.Active); err != nil {
			return nil, fmt.Errorf("scan vessel: %w", err)
		}
		vessels = append(vessels, vessel)
	}
	return vessels, rows.Err()
}

// GetVessel returns one operator-scoped vessel; ErrNotFound when absent or
// owned by another operator (no cross-tenant existence leak).
func (store *PostgresStore) GetVessel(ctx context.Context, operatorID, vesselID string) (Vessel, error) {
	var vessel Vessel
	err := store.pool.QueryRow(ctx,
		`SELECT vessel_id, operator_id, vessel_name, COALESCE(imo_number, ''), capacity, active
		 FROM vessels WHERE vessel_id = $1 AND operator_id = $2`, vesselID, operatorID).
		Scan(&vessel.VesselID, &vessel.OperatorID, &vessel.Name, &vessel.IMONumber, &vessel.Capacity, &vessel.Active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Vessel{}, ErrNotFound
		}
		return Vessel{}, fmt.Errorf("load vessel: %w", err)
	}
	return vessel, nil
}

// UpdateVessel mutates name/IMO/capacity/active for an operator-scoped vessel.
func (store *PostgresStore) UpdateVessel(ctx context.Context, vessel Vessel) error {
	if vessel.Capacity <= 0 {
		return errors.New("vessel capacity must be positive")
	}
	result, err := store.pool.Exec(ctx,
		`UPDATE vessels SET vessel_name = $3, imo_number = NULLIF($4, ''), capacity = $5, active = $6
		 WHERE vessel_id = $1 AND operator_id = $2`,
		vessel.VesselID, vessel.OperatorID, vessel.Name, vessel.IMONumber, vessel.Capacity, vessel.Active)
	if err != nil {
		return fmt.Errorf("update vessel: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// DeleteVessel removes an operator-scoped vessel. It fails closed when the
// vessel has trips (safety history must be preserved).
func (store *PostgresStore) DeleteVessel(ctx context.Context, operatorID, vesselID string) error {
	result, err := store.pool.Exec(ctx,
		`DELETE FROM vessels WHERE vessel_id = $1 AND operator_id = $2
		 AND NOT EXISTS (SELECT 1 FROM trips WHERE trips.vessel_id = vessels.vessel_id)`,
		vesselID, operatorID)
	if err != nil {
		return fmt.Errorf("delete vessel: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// CreateTrip schedules one departure. Capacity is copied from the vessel at
// scheduling time so later vessel edits never retroactively overbook.
func (store *PostgresStore) CreateTrip(ctx context.Context, trip Trip) error {
	if trip.TripID == "" || trip.OperatorID == "" || trip.RouteReference == "" || trip.TerminalReference == "" {
		return errors.New("trip id, operator id, route and terminal references are required")
	}
	if trip.FareNGNMinor <= 0 {
		return errors.New("trip fare must be positive")
	}
	if trip.ScheduledDeparture.IsZero() {
		return errors.New("scheduled departure is required")
	}
	vessel, err := store.GetVessel(ctx, trip.OperatorID, trip.VesselID)
	if err != nil {
		return fmt.Errorf("load trip vessel: %w", err)
	}
	if !vessel.Active {
		return errors.New("vessel is not active")
	}
	trip.Capacity = vessel.Capacity
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO trips (trip_id, vessel_id, operator_id, route_reference, terminal_reference,
		     scheduled_departure, fare_ngn_minor, capacity, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'SCHEDULED')`,
		trip.TripID, trip.VesselID, trip.OperatorID, trip.RouteReference, trip.TerminalReference,
		trip.ScheduledDeparture, trip.FareNGNMinor, trip.Capacity); err != nil {
		return fmt.Errorf("insert trip: %w", err)
	}
	return nil
}

// ListTrips returns the operator's trips, most recent first.
func (store *PostgresStore) ListTrips(ctx context.Context, operatorID string) ([]Trip, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT trip_id, vessel_id, operator_id, route_reference, terminal_reference,
		        scheduled_departure, fare_ngn_minor, capacity, seats_reserved, status
		 FROM trips WHERE operator_id = $1 ORDER BY scheduled_departure DESC`, operatorID)
	if err != nil {
		return nil, fmt.Errorf("list trips: %w", err)
	}
	defer rows.Close()
	trips := make([]Trip, 0)
	for rows.Next() {
		var trip Trip
		if err := rows.Scan(&trip.TripID, &trip.VesselID, &trip.OperatorID, &trip.RouteReference,
			&trip.TerminalReference, &trip.ScheduledDeparture, &trip.FareNGNMinor, &trip.Capacity,
			&trip.SeatsReserved, &trip.Status); err != nil {
			return nil, fmt.Errorf("scan trip: %w", err)
		}
		trips = append(trips, trip)
	}
	return trips, rows.Err()
}

// GetTripScoped returns one operator-scoped trip.
func (store *PostgresStore) GetTripScoped(ctx context.Context, operatorID, tripID string) (Trip, error) {
	trip, err := store.GetTrip(ctx, tripID)
	if err != nil {
		return Trip{}, err
	}
	if trip.OperatorID != operatorID {
		return Trip{}, ErrNotFound
	}
	return trip, nil
}

// Dashboard aggregates tickets sold, revenue and per-corridor stats for the
// operator. Sold means PAID or ISSUED (terminal refund/void rows excluded).
func (store *PostgresStore) Dashboard(ctx context.Context, operatorID string) (Dashboard, error) {
	dashboard := Dashboard{OperatorID: operatorID, PerCorridorStats: make([]CorridorStat, 0)}
	err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*), 0), COALESCE(SUM(fare_ngn_minor), 0)
		 FROM tickets WHERE operator_id = $1 AND state IN ('PAID', 'ISSUED')`, operatorID).
		Scan(&dashboard.TicketsSold, &dashboard.RevenueNGNMinor)
	if err != nil {
		return Dashboard{}, fmt.Errorf("aggregate tickets: %w", err)
	}
	rows, err := store.pool.Query(ctx,
		`SELECT t.route_reference,
		        COALESCE(COUNT(k.ticket_id), 0),
		        COALESCE(SUM(k.fare_ngn_minor), 0),
		        COUNT(t.trip_id)
		 FROM trips t
		 LEFT JOIN tickets k ON k.trip_id = t.trip_id AND k.state IN ('PAID', 'ISSUED')
		 WHERE t.operator_id = $1
		 GROUP BY t.route_reference ORDER BY t.route_reference`, operatorID)
	if err != nil {
		return Dashboard{}, fmt.Errorf("aggregate corridors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var stat CorridorStat
		if err := rows.Scan(&stat.RouteReference, &stat.TicketsSold, &stat.RevenueNGNMinor, &stat.TripsScheduled); err != nil {
			return Dashboard{}, fmt.Errorf("scan corridor stat: %w", err)
		}
		dashboard.PerCorridorStats = append(dashboard.PerCorridorStats, stat)
	}
	return dashboard, rows.Err()
}

// MarkEmbarked records a boarded passenger on an operator-scoped ISSUED
// ticket (manifest completeness input).
func (store *PostgresStore) MarkEmbarked(ctx context.Context, operatorID, ticketID string) (Ticket, error) {
	result, err := store.pool.Exec(ctx,
		`UPDATE tickets SET embarked = TRUE, updated_at = now()
		 WHERE ticket_id = $1 AND operator_id = $2 AND state = 'ISSUED'`, ticketID, operatorID)
	if err != nil {
		return Ticket{}, fmt.Errorf("mark embarked: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Ticket{}, ErrNotFound
	}
	return store.GetTicket(ctx, ticketID)
}

// AppendEvent writes one standalone outbox event (workflow activities use it
// for weather alerts and manifest-incomplete audits).
func (store *PostgresStore) AppendEvent(ctx context.Context, event Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin outbox transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit outbox event: %w", err)
	}
	return nil
}

// MarkTripBoardingPaused flips a trip to BOARDING_PAUSED (adverse weather).
func (store *PostgresStore) MarkTripBoardingPaused(ctx context.Context, tripID string) error {
	result, err := store.pool.Exec(ctx,
		`UPDATE trips SET status = 'BOARDING_PAUSED' WHERE trip_id = $1 AND status = 'SCHEDULED'`, tripID)
	if err != nil {
		return fmt.Errorf("pause boarding: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("trip %s is not scheduled; boarding cannot be paused", tripID)
	}
	return nil
}
