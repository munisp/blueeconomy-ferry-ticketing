package ticketing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeStore is an in-memory Store honoring capacity and idempotency exactly
// like the PostgreSQL implementation contract.
type fakeStore struct {
	mu            sync.Mutex
	trips         map[string]Trip
	tickets       map[string]Ticket
	keys          map[string]string // idempotency key -> ticket id
	keyPrincipals map[string]string
	cashIns       []CashIn
	events        []Event
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		trips:         make(map[string]Trip),
		tickets:       make(map[string]Ticket),
		keys:          make(map[string]string),
		keyPrincipals: make(map[string]string),
	}
}

func (store *fakeStore) ReserveSeat(_ context.Context, ticket Ticket, idempotencyKey string, event Event) (*Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if bound, ok := store.keys[idempotencyKey]; ok {
		if store.keyPrincipals[idempotencyKey] != ticket.PurchaserPrincipal {
			return nil, ErrIdempotencyConflict
		}
		replayed := store.tickets[bound]
		return &replayed, nil
	}
	trip, ok := store.trips[ticket.TripID]
	if !ok {
		return nil, ErrNotFound
	}
	if trip.Status != "SCHEDULED" {
		return nil, fmt.Errorf("trip is not open for purchase (status %s)", trip.Status)
	}
	if trip.SeatsReserved >= trip.Capacity {
		return nil, ErrCapacityExceeded
	}
	trip.SeatsReserved++
	store.trips[ticket.TripID] = trip
	seat := trip.SeatsReserved
	ticket.SeatNumber = &seat
	store.tickets[ticket.TicketID] = ticket
	store.keys[idempotencyKey] = ticket.TicketID
	store.keyPrincipals[idempotencyKey] = ticket.PurchaserPrincipal
	store.events = append(store.events, event)
	return nil, nil
}

func (store *fakeStore) GetTicket(_ context.Context, ticketID string) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[ticketID]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	return ticket, nil
}

func (store *fakeStore) transition(ticketID string, version int64, to State) (Ticket, error) {
	ticket, ok := store.tickets[ticketID]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	if ticket.Version != version {
		return Ticket{}, fmt.Errorf("ticket version conflict")
	}
	if !ValidTransition(ticket.State, to) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, to)
	}
	ticket.State = to
	ticket.Version = version + 1
	store.tickets[ticketID] = ticket
	return ticket, nil
}

func (store *fakeStore) MarkPaid(_ context.Context, ticketID string, version int64, ledgerPostID string, cashIn *CashIn, events []Event) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, err := store.transition(ticketID, version, StatePaid)
	if err != nil {
		return Ticket{}, err
	}
	ticket.LedgerPostID = ledgerPostID
	store.tickets[ticketID] = ticket
	if cashIn != nil {
		store.cashIns = append(store.cashIns, *cashIn)
	}
	store.events = append(store.events, events...)
	return ticket, nil
}

func (store *fakeStore) MarkIssued(_ context.Context, ticketID string, version int64, seatNumber int, event Event) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, err := store.transition(ticketID, version, StateIssued)
	if err != nil {
		return Ticket{}, err
	}
	if seatNumber > 0 {
		ticket.SeatNumber = &seatNumber
		store.tickets[ticketID] = ticket
	}
	store.events = append(store.events, event)
	return ticket, nil
}

func (store *fakeStore) Transition(_ context.Context, ticketID string, version int64, to State, event Event) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, err := store.transition(ticketID, version, to)
	if err != nil {
		return Ticket{}, err
	}
	store.events = append(store.events, event)
	return ticket, nil
}

func (store *fakeStore) GetTrip(_ context.Context, tripID string) (Trip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	trip, ok := store.trips[tripID]
	if !ok {
		return Trip{}, ErrNotFound
	}
	return trip, nil
}

// fakeLedger records reserve/post/void/refund calls.
type fakeLedger struct {
	mu         sync.Mutex
	reserved   []string
	posted     []string
	voided     []string
	refunded   []string
	reserveErr error
	postErr    error
}

func (ledger *fakeLedger) Reserve(_ context.Context, ticketID string, _ Channel, _ int64) (string, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.reserveErr != nil {
		return "", ledger.reserveErr
	}
	ledger.reserved = append(ledger.reserved, ticketID)
	return "reserve-" + ticketID, nil
}

func (ledger *fakeLedger) Post(_ context.Context, reserveID string) (string, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.postErr != nil {
		return "", ledger.postErr
	}
	ledger.posted = append(ledger.posted, reserveID)
	return "post-" + reserveID, nil
}

func (ledger *fakeLedger) Void(_ context.Context, reserveID string) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.voided = append(ledger.voided, reserveID)
	return nil
}

func (ledger *fakeLedger) Refund(_ context.Context, ticketID string, _ int64) (string, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.refunded = append(ledger.refunded, ticketID)
	return "refund-" + ticketID, nil
}

const testSalt = "0123456789abcdef"

func seededService(t *testing.T) (*Service, *fakeStore, *fakeLedger) {
	t.Helper()
	store := newFakeStore()
	store.trips["trip-1"] = Trip{
		TripID: "trip-1", VesselID: "vessel-1", OperatorID: "op-1",
		RouteReference: "route-lagos-badagry", TerminalReference: "terminal-1",
		ScheduledDeparture: time.Now().Add(2 * time.Hour), FareNGNMinor: 250000,
		Capacity: 2, Status: "SCHEDULED",
	}
	ledger := &fakeLedger{}
	service, err := NewService(store, ledger, testSalt)
	require.NoError(t, err)
	return service, store, ledger
}

func purchaseRequest(key string) PurchaseRequest {
	return PurchaseRequest{
		TripID: "trip-1", PassengerRef: "passenger-" + key, Channel: ChannelDirect,
		IdempotencyKey: key, CorrelationID: "corr-" + key, Principal: "subject-1",
		PrincipalRole: "passenger",
	}
}

func TestNewServiceFailsClosed(t *testing.T) {
	_, err := NewService(nil, &fakeLedger{}, testSalt)
	require.Error(t, err)
	_, err = NewService(newFakeStore(), nil, testSalt)
	require.Error(t, err)
	_, err = NewService(newFakeStore(), &fakeLedger{}, "short")
	require.Error(t, err)
}

func TestPurchaseIssuesTicketWithSeatAndLedgerFlow(t *testing.T) {
	service, store, ledger := seededService(t)
	ticket, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	require.Equal(t, StateIssued, ticket.State)
	require.NotNil(t, ticket.SeatNumber)
	require.Equal(t, 1, *ticket.SeatNumber)
	require.Equal(t, "reserve-"+ticket.TicketID, ticket.LedgerReserveID)
	require.Len(t, ledger.reserved, 1)
	require.Len(t, ledger.posted, 1)
	require.Empty(t, ledger.voided)
	// Outbox events: reserved, paid, issued.
	types := make([]string, 0, len(store.events))
	for _, event := range store.events {
		types = append(types, event.EventType)
		require.Equal(t, TopicTicketing, event.Topic)
	}
	require.Equal(t, []string{EventTicketReserved, EventTicketPaid, EventTicketIssued}, types)
}

func TestPurchaseIsIdempotent(t *testing.T) {
	service, store, ledger := seededService(t)
	first, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	second, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	require.Equal(t, first.TicketID, second.TicketID)
	// Replay capacity is not double-consumed; the duplicate ledger reserve is
	// voided as compensation.
	require.Equal(t, 1, store.trips["trip-1"].SeatsReserved)
	require.Len(t, ledger.reserved, 2)
	require.Len(t, ledger.voided, 1)
}

func TestPurchaseCapacityIsEnforced(t *testing.T) {
	service, store, ledger := seededService(t)
	_, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	_, err = service.Purchase(context.Background(), purchaseRequest("key-2"))
	require.NoError(t, err)
	_, err = service.Purchase(context.Background(), purchaseRequest("key-3"))
	require.ErrorIs(t, err, ErrCapacityExceeded)
	require.Equal(t, 2, store.trips["trip-1"].SeatsReserved, "no overbooking")
	// The failed purchase's ledger reserve was voided as compensation.
	require.Len(t, ledger.voided, 1)
}

func TestPurchaseAgentCashInRecordsLedgerEvent(t *testing.T) {
	service, store, _ := seededService(t)
	request := purchaseRequest("key-agent")
	request.Channel = ChannelAgentCashIn
	request.AgentID = "agent-7"
	ticket, err := service.Purchase(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, ChannelAgentCashIn, ticket.Channel)
	require.Len(t, store.cashIns, 1)
	require.Equal(t, "agent-7", store.cashIns[0].AgentID)
	require.Equal(t, ticket.FareNGNMinor, store.cashIns[0].AmountNGNMinor)
	found := false
	for _, event := range store.events {
		if event.EventType == EventAgentCashIn {
			found = true
		}
	}
	require.True(t, found, "cash-in ledger event must be published")
}

func TestPurchaseFailsClosedOnLedgerOutage(t *testing.T) {
	service, _, ledger := seededService(t)
	ledger.reserveErr = errors.New("tigerbeetle unreachable")
	_, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.Error(t, err)
}

func TestRefundTransitionsAndPostsRefund(t *testing.T) {
	service, _, ledger := seededService(t)
	ticket, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	refunded, err := service.Refund(context.Background(), ticket.TicketID, "subject-1", "passenger", "corr-refund")
	require.NoError(t, err)
	require.Equal(t, StateRefunded, refunded.State)
	require.Len(t, ledger.refunded, 1)
	// Terminal: a second refund fails closed.
	_, err = service.Refund(context.Background(), ticket.TicketID, "subject-1", "passenger", "corr-refund-2")
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestVoidReleasesPendingReserve(t *testing.T) {
	service, store, ledger := seededService(t)
	// Simulate a RESERVED-only ticket (post failed after reserve).
	store.tickets["ticket-r"] = Ticket{
		TicketID: "ticket-r", TripID: "trip-1", OperatorID: "op-1", State: StateReserved,
		Version: 1, LedgerReserveID: "reserve-ticket-r", FareNGNMinor: 250000,
		PurchaserPrincipal: "subject-1", Channel: ChannelDirect, PassengerDigest: "digest",
	}
	voided, err := service.Void(context.Background(), "ticket-r", "corr-void")
	require.NoError(t, err)
	require.Equal(t, StateVoid, voided.State)
	require.Contains(t, ledger.voided, "reserve-ticket-r")
}
