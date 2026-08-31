//go:build integration

package ticketing

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestSuspensionStoreIntegration exercises the met-ocean suspension path
// against a real PostgreSQL: windowed open-departure lookup, transactional
// suspend (state + audit + notification outbox), idempotent replay,
// multi-advisory resume guarding and outbox entries. Requires
// FERRY_TEST_DATABASE_URL (integration/compose.yaml).
func TestSuspensionStoreIntegration(t *testing.T) {
	ctx := context.Background()
	pool := openIntegrationPool(t, ctx)
	defer pool.Close()
	store, err := NewPostgresStore(pool)
	require.NoError(t, err)

	seedTrip(t, ctx, pool, "op-susp", "vessel-susp", "trip-susp-1", 50)
	// Second departure on the same route, inside the window.
	if _, err := pool.Exec(ctx,
		`INSERT INTO trips (trip_id, vessel_id, operator_id, route_reference, terminal_reference, scheduled_departure, fare_ngn_minor, capacity)
		 VALUES ('trip-susp-2', 'vessel-susp', 'op-susp', 'route-int', 'terminal-int', $1, 250000, 50)`,
		time.Now().Add(26*time.Hour).UTC()); err != nil {
		t.Fatalf("insert second trip: %v", err)
	}

	from := time.Now().Add(12 * time.Hour).UTC()
	until := time.Now().Add(48 * time.Hour).UTC()

	// The window covers both open departures on route-int.
	departures, err := store.ListOpenDeparturesInWindow(ctx, "route-int", from, until)
	require.NoError(t, err)
	require.Len(t, departures, 2)

	suspension := TripSuspension{
		TripID:            "trip-susp-1",
		AdvisoryID:        "moa-int-1",
		Severity:          "Severe",
		PhenomenonCode:    "HIGH_SIGNIFICANT_WAVE_HEIGHT",
		ZoneID:            "hz-lagos-approach",
		EffectiveFrom:     from,
		EffectiveUntil:    until,
		BulletinReference: "sha256:abc",
	}
	notification := func(tripID, eventType string) Event {
		return Event{
			EventID:       uuid.NewString(),
			Topic:         TopicNotifications,
			SubjectID:     tripID,
			EventType:     eventType,
			CorrelationID: "corr-int-1",
			Payload:       map[string]any{"trip_id": tripID, "advisory_id": suspension.AdvisoryID},
		}
	}

	// Suspend: state transition + audit + notification, atomically.
	newly, err := store.SuspendDeparture(ctx, suspension, "corr-int-1", notification("trip-susp-1", EventDepartureSuspended))
	require.NoError(t, err)
	require.True(t, newly)
	trip, err := store.GetTrip(ctx, "trip-susp-1")
	require.NoError(t, err)
	require.Equal(t, "SUSPENDED", trip.Status)

	// Replay of the same (trip, advisory) is an idempotent no-op.
	newly, err = store.SuspendDeparture(ctx, suspension, "corr-int-1", notification("trip-susp-1", EventDepartureSuspended))
	require.NoError(t, err)
	require.False(t, newly)

	// A second advisory binds to the same trip without a second transition.
	other := suspension
	other.AdvisoryID = "moa-int-2"
	newly, err = store.SuspendDeparture(ctx, other, "corr-int-2", notification("trip-susp-1", EventDepartureSuspended))
	require.NoError(t, err)
	require.False(t, newly)
	trip, err = store.GetTrip(ctx, "trip-susp-1")
	require.NoError(t, err)
	require.Equal(t, "SUSPENDED", trip.Status)

	// Resuming the first advisory alone must not reopen the trip: the second
	// advisory still suspends it.
	resumed, err := store.ResumeDeparturesForAdvisory(ctx, "moa-int-1", "corr-resume-1", func(tripID string) Event {
		return notification(tripID, EventDepartureResumed)
	})
	require.NoError(t, err)
	require.Empty(t, resumed)
	trip, err = store.GetTrip(ctx, "trip-susp-1")
	require.NoError(t, err)
	require.Equal(t, "SUSPENDED", trip.Status)

	// Resuming the second advisory reopens the trip and notifies.
	resumed, err = store.ResumeDeparturesForAdvisory(ctx, "moa-int-2", "corr-resume-2", func(tripID string) Event {
		return notification(tripID, EventDepartureResumed)
	})
	require.NoError(t, err)
	require.Equal(t, []string{"trip-susp-1"}, resumed)
	trip, err = store.GetTrip(ctx, "trip-susp-1")
	require.NoError(t, err)
	require.Equal(t, "SCHEDULED", trip.Status)

	// Resume is idempotent.
	resumed, err = store.ResumeDeparturesForAdvisory(ctx, "moa-int-2", "corr-resume-2", func(tripID string) Event {
		return notification(tripID, EventDepartureResumed)
	})
	require.NoError(t, err)
	require.Empty(t, resumed)

	// The audit trail retains both suspensions with resume markers.
	var auditRows, resumedRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(resumed_at) FROM trip_suspensions WHERE trip_id = 'trip-susp-1'`).
		Scan(&auditRows, &resumedRows))
	require.Equal(t, 2, auditRows)
	require.Equal(t, 2, resumedRows)

	// Notification outbox: one suspension and one resumption entry, on the
	// approved notifications topic.
	var suspendedEvents, resumedEvents int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE event_type = 'ferry.trip.departure_suspended'),
		   COUNT(*) FILTER (WHERE event_type = 'ferry.trip.departure_resumed')
		 FROM ferry_outbox WHERE topic = 'ferries.notifications.v1' AND subject_id = 'trip-susp-1'`).
		Scan(&suspendedEvents, &resumedEvents))
	require.Equal(t, 1, suspendedEvents)
	require.Equal(t, 1, resumedEvents)

	// A departed trip can no longer be suspended (late advisory is a no-op).
	require.NoError(t, store.MarkTripDeparted(ctx, "trip-susp-1"))
	newly, err = store.SuspendDeparture(ctx, suspension, "corr-late", notification("trip-susp-1", EventDepartureSuspended))
	require.NoError(t, err)
	require.False(t, newly)
}
