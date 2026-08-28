package ticketing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

const boardingWindowSecret = "boarding-test-window-secret-0123456789"

var boardingNow = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

// fakeBoardingStore is an in-memory BoardingStore honoring the atomic
// first-scan-wins consume contract.
type fakeBoardingStore struct {
	mu      sync.Mutex
	tickets map[string]Ticket
	trips   map[string]Trip
	events  []Event
}

func newFakeBoardingStore() *fakeBoardingStore {
	return &fakeBoardingStore{tickets: make(map[string]Ticket), trips: make(map[string]Trip)}
}

func (store *fakeBoardingStore) seed(ticket Ticket, trip Trip) {
	store.tickets[ticket.TicketID] = ticket
	store.trips[trip.TripID] = trip
}

func (store *fakeBoardingStore) GetTicket(_ context.Context, ticketID string) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[ticketID]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	return ticket, nil
}

func (store *fakeBoardingStore) GetTrip(_ context.Context, tripID string) (Trip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	trip, ok := store.trips[tripID]
	if !ok {
		return Trip{}, ErrNotFound
	}
	return trip, nil
}

func (store *fakeBoardingStore) ConsumeBoarding(_ context.Context, operatorID, ticketID, boardedBy, artifactKid string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[ticketID]
	if !ok || ticket.OperatorID != operatorID || ticket.State != StateIssued || ticket.BoardedAt != nil {
		return false, nil
	}
	boarded := boardingNow
	ticket.Embarked = true
	ticket.BoardedAt = &boarded
	ticket.BoardedBy = boardedBy
	ticket.ArtifactKid = artifactKid
	store.tickets[ticketID] = ticket
	return true, nil
}

func (store *fakeBoardingStore) AppendEvent(_ context.Context, event Event) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.events = append(store.events, event)
	return nil
}

func (store *fakeBoardingStore) fraudEvents() []Event {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]Event(nil), store.events...)
}

func newBoardingFixture(t *testing.T) (*BoardingService, *fakeBoardingStore, *ticketproof.KeySet) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySet, err := ticketproof.NewKeySet(key, 1, nil)
	require.NoError(t, err)
	store := newFakeBoardingStore()
	service, err := NewBoardingService(store, keySet, boardingWindowSecret)
	require.NoError(t, err)
	service.now = func() time.Time { return boardingNow }
	seat := 12
	store.seed(Ticket{
		TicketID: "ticket-1", TripID: "trip-1", OperatorID: "op-1", State: StateIssued,
		PassengerDigest: strings.Repeat("b", 64), SeatNumber: &seat, PurchaserPrincipal: "subject-1",
	}, Trip{
		TripID: "trip-1", OperatorID: "op-1", Status: "SCHEDULED",
		ScheduledDeparture: boardingNow.Add(2 * time.Hour),
	})
	return service, store, keySet
}

func TestBoardingFailsClosedWithoutDependencies(t *testing.T) {
	_, err := NewBoardingService(nil, nil, boardingWindowSecret)
	require.Error(t, err)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySet, err := ticketproof.NewKeySet(key, 1, nil)
	require.NoError(t, err)
	_, err = NewBoardingService(newFakeBoardingStore(), nil, boardingWindowSecret)
	require.Error(t, err)
	_, err = NewBoardingService(newFakeBoardingStore(), keySet, "short")
	require.Error(t, err)
	_, err = NewBoardingService(newFakeBoardingStore(), keySet, boardingWindowSecret)
	require.NoError(t, err)
}

func TestMintVerifyEmbarkRoundTrip(t *testing.T) {
	service, store, keySet := newBoardingFixture(t)
	artifact, err := service.MintArtifact(context.Background(), "ticket-1")
	require.NoError(t, err)
	require.Equal(t, keySet.CurrentKeyID(), artifact.KeyID)
	require.Equal(t, uint32(1), artifact.RotationEpoch)
	require.Equal(t, boardingNow.Add(2*time.Hour), artifact.ExpiresAt)

	// Stateless verify needs no store interaction.
	payload, err := service.VerifyArtifact(context.Background(), artifact.Token, "gate-1", "corr-1")
	require.NoError(t, err)
	require.Equal(t, "ticket-1", payload.TicketID)
	require.Equal(t, 12, payload.Seat)

	boarded, err := service.Embark(context.Background(), "op-1", "ticket-1", artifact.Token, "op-subject", "corr-2")
	require.NoError(t, err)
	require.True(t, boarded.Embarked)
	require.NotNil(t, boarded.BoardedAt)
	require.Equal(t, "op-subject", boarded.BoardedBy)
	require.Equal(t, keySet.CurrentKeyID(), boarded.ArtifactKid)
	require.Empty(t, store.fraudEvents())
}

func TestMintRequiresIssuedState(t *testing.T) {
	service, store, _ := newBoardingFixture(t)
	ticket := store.tickets["ticket-1"]
	ticket.State = StatePaid
	store.tickets["ticket-1"] = ticket
	_, err := service.MintArtifact(context.Background(), "ticket-1")
	require.ErrorIs(t, err, ErrInvalidTransition)
	_, err = service.MintArtifact(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDuplicatePresentationEmitsFraudEvent(t *testing.T) {
	service, store, _ := newBoardingFixture(t)
	artifact, err := service.MintArtifact(context.Background(), "ticket-1")
	require.NoError(t, err)
	_, err = service.Embark(context.Background(), "op-1", "ticket-1", artifact.Token, "gate-a", "corr-1")
	require.NoError(t, err)

	_, err = service.Embark(context.Background(), "op-1", "ticket-1", artifact.Token, "gate-b", "corr-2")
	require.ErrorIs(t, err, ErrBoardingAlreadyConsumed)
	events := store.fraudEvents()
	require.Len(t, events, 1)
	require.Equal(t, EventTicketDuplicatePresentation, events[0].EventType)
	require.Equal(t, TopicTicketing, events[0].Topic)
	require.Equal(t, "ticket-1", events[0].SubjectID)
	require.Equal(t, "corr-2", events[0].CorrelationID)
	require.Equal(t, "gate-b", events[0].Payload["principal_id"])
	require.Equal(t, "gate-a", events[0].Payload["first_boarded_by"])
	require.Equal(t, "trip-1", events[0].Payload["trip_id"])
}

func TestEmbarkConcurrentFirstScanWins(t *testing.T) {
	service, _, _ := newBoardingFixture(t)
	artifact, err := service.MintArtifact(context.Background(), "ticket-1")
	require.NoError(t, err)

	// Two gangways consume the same artifact concurrently: exactly one wins.
	const gangways = 8
	var start sync.WaitGroup
	start.Add(1)
	outcomes := make(chan error, gangways)
	for index := 0; index < gangways; index++ {
		go func(gate string) {
			start.Wait()
			_, err := service.Embark(context.Background(), "op-1", "ticket-1", artifact.Token, gate, "corr-"+gate)
			outcomes <- err
		}(fmt.Sprintf("gate-%d", index))
	}
	start.Done()
	wins, duplicates := 0, 0
	for index := 0; index < gangways; index++ {
		err := <-outcomes
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrBoardingAlreadyConsumed):
			duplicates++
		default:
			t.Fatalf("unexpected outcome: %v", err)
		}
	}
	require.Equal(t, 1, wins, "exactly one presentation boards")
	require.Equal(t, gangways-1, duplicates, "every other presentation is a 409 duplicate")
}

func TestEmbarkRejectsInvalidArtifactsWithTelemetry(t *testing.T) {
	service, store, _ := newBoardingFixture(t)

	// Unknown kid (signed by a rogue key).
	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rogueSet, err := ticketproof.NewKeySet(rogue, 1, nil)
	require.NoError(t, err)
	rogueToken, err := rogueSet.Sign(ticketproof.Payload{
		TicketID: "ticket-1", TripID: "trip-1", Seat: 12, IssuedAt: boardingNow,
		ExpiresAt: boardingNow.Add(time.Hour), HolderDigest: strings.Repeat("b", 64),
	}, boardingWindowSecret, boardingNow)
	require.NoError(t, err)
	_, err = service.Embark(context.Background(), "op-1", "ticket-1", rogueToken, "gate-a", "corr-1")
	require.ErrorIs(t, err, ErrTicketProofInvalid)

	// Stale window code (static screenshot replayed after tolerance).
	stale, err := service.MintArtifact(context.Background(), "ticket-1")
	require.NoError(t, err)
	service.now = func() time.Time { return boardingNow.Add(5 * time.Minute) }
	_, err = service.Embark(context.Background(), "op-1", "ticket-1", stale.Token, "gate-a", "corr-2")
	require.ErrorIs(t, err, ErrTicketProofInvalid)
	service.now = func() time.Time { return boardingNow }

	events := store.fraudEvents()
	require.Len(t, events, 2)
	require.Equal(t, EventTicketVerificationFailed, events[0].EventType)
	require.Equal(t, "unknown_kid", events[0].Payload["reason"])
	require.Equal(t, "window_code_invalid", events[1].Payload["reason"])

	// No boarding was consumed by the rejected presentations.
	ticket, err := store.GetTicket(context.Background(), "ticket-1")
	require.NoError(t, err)
	require.Nil(t, ticket.BoardedAt)
}

func TestEmbarkLegacyPath(t *testing.T) {
	service, _, _ := newBoardingFixture(t)
	boarded, err := service.Embark(context.Background(), "op-1", "ticket-1", "", "op-subject", "corr-1")
	require.NoError(t, err)
	require.True(t, boarded.Embarked)
	require.Empty(t, boarded.ArtifactKid, "legacy path records no artifact kid")

	_, err = service.Embark(context.Background(), "op-1", "ticket-1", "", "op-subject", "corr-2")
	require.ErrorIs(t, err, ErrBoardingAlreadyConsumed)

	// Wrong operator scope: no existence leak.
	_, err = service.Embark(context.Background(), "op-2", "ticket-1", "", "op-stranger", "corr-3")
	require.ErrorIs(t, err, ErrNotFound)
}
