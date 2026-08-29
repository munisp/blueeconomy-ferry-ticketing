package ticketing

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	// markPaidErr injects a MarkPaid failure (purchase-saga fault injection).
	markPaidErr error
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
	if to.Terminal() {
		// Mirrors the PostgreSQL contract: a terminal transition releases the
		// seat atomically; the state graph makes double-decrement impossible.
		trip := store.trips[ticket.TripID]
		if trip.SeatsReserved > 0 {
			trip.SeatsReserved--
			store.trips[ticket.TripID] = trip
		}
	}
	ticket.State = to
	ticket.Version = version + 1
	store.tickets[ticketID] = ticket
	return ticket, nil
}

func (store *fakeStore) MarkPaid(_ context.Context, ticketID string, version int64, ledgerPostID string, cashIn *CashIn, events []Event) (Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.markPaidErr != nil {
		return Ticket{}, store.markPaidErr
	}
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

func (store *fakeStore) listByStateBefore(state State, cutoff time.Time, limit int, useUpdated bool) []Ticket {
	out := make([]Ticket, 0)
	for _, ticket := range store.tickets {
		at := ticket.CreatedAt
		if useUpdated {
			at = ticket.UpdatedAt
		}
		if ticket.State == state && at.Before(cutoff) {
			out = append(out, ticket)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if useUpdated {
			return out[i].UpdatedAt.Before(out[j].UpdatedAt)
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (store *fakeStore) ListReservedBefore(_ context.Context, cutoff time.Time, limit int) ([]Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.listByStateBefore(StateReserved, cutoff, limit, false), nil
}

func (store *fakeStore) ListUnissuedPaidBefore(_ context.Context, cutoff time.Time, limit int) ([]Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.listByStateBefore(StatePaid, cutoff, limit, true), nil
}

// fakeLedger records reserve/post/void/refund calls and resolves reserve
// state from those records exactly like the TigerBeetle boundary contract:
// posted beats voided, an auto-voided (timed-out) pending reserve resolves as
// released.
type fakeLedger struct {
	mu         sync.Mutex
	reserved   []string
	posted     []string
	voided     []string
	refunded   []string
	reserveErr      error
	postErr         error
	resolveErr      error
	refundedAmounts []int64
	// timedOut simulates pending reserves auto-voided by the TigerBeetle
	// pending-transfer timeout (no void transfer is recorded cluster-side).
	timedOut map[string]bool
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

func (ledger *fakeLedger) Refund(_ context.Context, ticketID string, amount int64) (string, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	ledger.refunded = append(ledger.refunded, ticketID)
	ledger.refundedAmounts = append(ledger.refundedAmounts, amount)
	return "refund-" + ticketID, nil
}

func (ledger *fakeLedger) ResolveReserve(_ context.Context, reserveID string) (ReserveResolution, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.resolveErr != nil {
		return ReserveResolution{}, ledger.resolveErr
	}
	contains := func(list []string) bool {
		for _, candidate := range list {
			if candidate == reserveID {
				return true
			}
		}
		return false
	}
	switch {
	case contains(ledger.posted):
		return ReserveResolution{Status: ReserveStatusPosted, PostTransferID: "post-" + reserveID}, nil
	case contains(ledger.voided) || ledger.timedOut[reserveID]:
		return ReserveResolution{Status: ReserveStatusReleased}, nil
	case contains(ledger.reserved):
		return ReserveResolution{Status: ReserveStatusPending}, nil
	default:
		return ReserveResolution{Status: ReserveStatusUnknown}, nil
	}
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
	require.Equal(t, []int64{ticket.FareNGNMinor}, ledger.refundedAmounts, "balanced: the refund moves exactly the fare back")
	// Terminal: a second refund fails closed.
	_, err = service.Refund(context.Background(), ticket.TicketID, "subject-1", "passenger", "corr-refund-2")
	require.ErrorIs(t, err, ErrInvalidTransition)
}

// TestRefundBoardedTicketRejected is the FE-3 regression: a ticket whose
// boarding was consumed can never be refunded — no ledger movement, no state
// change — regardless of whether the boarding is observed via boarded_at or
// the embarked flag.
func TestRefundBoardedTicketRejected(t *testing.T) {
	service, store, ledger := seededService(t)
	ticket, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	require.Equal(t, StateIssued, ticket.State)

	// First-scan-wins boarding record consumed.
	now := time.Now().UTC()
	boarded, _ := store.GetTicket(context.Background(), ticket.TicketID)
	boarded.Embarked = true
	boarded.BoardedAt = &now
	boarded.BoardedBy = "gate-1"
	store.tickets[ticket.TicketID] = boarded

	_, err = service.Refund(context.Background(), ticket.TicketID, "subject-1", "passenger", "corr-refund")
	require.ErrorIs(t, err, ErrTicketBoarded)
	require.Empty(t, ledger.refunded, "no refund transfer for a traveled passenger")
	unchanged, _ := store.GetTicket(context.Background(), ticket.TicketID)
	require.Equal(t, StateIssued, unchanged.State)

	// boarded_at alone (embarked flag cleared by a partial migration) also blocks.
	boarded.Embarked = false
	store.tickets[ticket.TicketID] = boarded
	_, err = service.Refund(context.Background(), ticket.TicketID, "subject-1", "passenger", "corr-refund")
	require.ErrorIs(t, err, ErrTicketBoarded)
	require.Empty(t, ledger.refunded)
}

// TestPurchaseReplayResumesInterruptedSaga proves the FE-1 retry-convergence
// contract: a replayed idempotency key whose stored ticket is still RESERVED
// (a previous attempt died after ReserveSeat) is driven through settlement
// and issuance instead of being returned stranded.
func TestPurchaseReplayResumesInterruptedSaga(t *testing.T) {
	service, store, ledger := seededService(t)
	// First attempt dies after the seat reservation: RESERVED ticket with a
	// pending reserve, no post, no payment.
	ticket := Ticket{
		TicketID: "ticket-interrupted", TripID: "trip-1", OperatorID: "op-1",
		PassengerDigest: "digest", FareNGNMinor: 250000, Channel: ChannelDirect,
		State: StateReserved, Version: 1, LedgerReserveID: "reserve-ticket-interrupted",
		PurchaserPrincipal: "subject-1", CorrelationID: "corr-key-1",
	}
	_, err := store.ReserveSeat(context.Background(), ticket, "key-1", Event{
		EventID: "evt-1", Topic: TopicTicketing, SubjectID: ticket.TicketID,
		EventType: EventTicketReserved, CorrelationID: ticket.CorrelationID,
		Payload: map[string]any{"ticket_id": ticket.TicketID},
	})
	require.NoError(t, err)
	replayed, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	require.Equal(t, StateIssued, replayed.State, "replay must resume the saga, not return a stranded RESERVED ticket")
	require.Equal(t, ticket.TicketID, replayed.TicketID)
	require.Contains(t, ledger.posted, "reserve-ticket-interrupted", "the ORIGINAL reserve is settled")
	require.Len(t, ledger.voided, 1, "the duplicate reserve from the replay is voided")
	require.Len(t, ledger.reserved, 1)
}

// TestPurchaseMarkPaidFailureReconcilesAndRetryConverges is the FE-1 fault
// injection: Post succeeds (irreversible) and MarkPaid fails. The reconciler
// must converge money and ticket state (ticket reaches PAID/ISSUED; the
// charge is honored), and an idempotent retry returns the converged ticket.
func TestPurchaseMarkPaidFailureReconcilesAndRetryConverges(t *testing.T) {
	service, store, ledger := seededService(t)
	store.markPaidErr = errors.New("postgres connection reset")
	_, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.Error(t, err, "the half-commit surfaces as an error")

	// Diverged: reserve posted on the ledger, ticket still RESERVED.
	var stranded Ticket
	for _, candidate := range store.tickets {
		stranded = candidate
	}
	require.Equal(t, StateReserved, stranded.State)
	require.Len(t, ledger.posted, 1, "the post is irreversible and already settled")

	// The reconciler completes the posted divergence.
	store.markPaidErr = nil
	report, err := service.Reconcile(context.Background(), 0, 0, 10)
	require.NoError(t, err)
	require.Equal(t, 1, report.Completed)
	require.Zero(t, report.Failed)
	recovered, err := store.GetTicket(context.Background(), stranded.TicketID)
	require.NoError(t, err)
	require.Equal(t, StateIssued, recovered.State, "charged passenger receives the issued ticket")
	require.Equal(t, "post-"+stranded.LedgerReserveID, recovered.LedgerPostID)

	// The idempotent retry converges to the same issued ticket.
	retry, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	require.Equal(t, recovered.TicketID, retry.TicketID)
	require.Equal(t, StateIssued, retry.State)
	require.Len(t, ledger.posted, 1, "no double charge across failure, reconciliation and retry")
}

// TestReconcileExpiresAutoVoidedReservation is the FE-5 sweep: a RESERVED
// ticket whose pending reserve auto-voided via the TigerBeetle timeout can
// never be paid; the reconciler expires it and frees the seat.
func TestReconcileExpiresAutoVoidedReservation(t *testing.T) {
	service, store, ledger := seededService(t)
	store.trips["trip-1"] = Trip{
		TripID: "trip-1", VesselID: "vessel-1", OperatorID: "op-1",
		RouteReference: "route-lagos-badagry", TerminalReference: "terminal-1",
		ScheduledDeparture: time.Now().Add(2 * time.Hour), FareNGNMinor: 250000,
		Capacity: 2, SeatsReserved: 1, Status: "SCHEDULED",
	}
	aged := time.Now().Add(-time.Hour).UTC()
	store.tickets["ticket-aged"] = Ticket{
		TicketID: "ticket-aged", TripID: "trip-1", OperatorID: "op-1",
		PassengerDigest: "digest", FareNGNMinor: 250000, Channel: ChannelDirect,
		State: StateReserved, Version: 1, LedgerReserveID: "reserve-ticket-aged",
		PurchaserPrincipal: "subject-1", CorrelationID: "corr-aged", CreatedAt: aged,
	}
	ledger.timedOut = map[string]bool{"reserve-ticket-aged": true}

	report, err := service.Reconcile(context.Background(), time.Minute, 30*time.Minute, 10)
	require.NoError(t, err)
	require.Equal(t, 1, report.Expired)
	require.Zero(t, report.Failed)
	expired, err := store.GetTicket(context.Background(), "ticket-aged")
	require.NoError(t, err)
	require.Equal(t, StateExpired, expired.State)
	require.Equal(t, 0, store.trips["trip-1"].SeatsReserved, "expiry releases the reserved seat")

	// A still-pending reserve within its timeout is left for a later sweep.
	store.tickets["ticket-fresh"] = Ticket{
		TicketID: "ticket-fresh", TripID: "trip-1", OperatorID: "op-1",
		PassengerDigest: "digest", FareNGNMinor: 250000, Channel: ChannelDirect,
		State: StateReserved, Version: 1, LedgerReserveID: "reserve-ticket-fresh",
		PurchaserPrincipal: "subject-1", CorrelationID: "corr-fresh",
		CreatedAt: time.Now().Add(-2 * time.Minute).UTC(),
	}
	ledger.reserved = append(ledger.reserved, "reserve-ticket-fresh")
	report, err = service.Reconcile(context.Background(), time.Minute, 30*time.Minute, 10)
	require.NoError(t, err)
	require.Equal(t, 1, report.Pending)
	require.Zero(t, report.Expired)
	fresh, err := store.GetTicket(context.Background(), "ticket-fresh")
	require.NoError(t, err)
	require.Equal(t, StateReserved, fresh.State)
}

// TestReconcileIssuesInterruptedPaidTicket covers purchases interrupted
// between payment and issuance (MarkIssued failed after MarkPaid).
func TestReconcileIssuesInterruptedPaidTicket(t *testing.T) {
	service, store, _ := seededService(t)
	store.tickets["ticket-paid"] = Ticket{
		TicketID: "ticket-paid", TripID: "trip-1", OperatorID: "op-1",
		PassengerDigest: "digest", FareNGNMinor: 250000, Channel: ChannelDirect,
		State: StatePaid, Version: 2, LedgerReserveID: "reserve-ticket-paid",
		LedgerPostID: "post-reserve-ticket-paid",
		PurchaserPrincipal: "subject-1", CorrelationID: "corr-paid",
	}
	report, err := service.Reconcile(context.Background(), 0, 0, 10)
	require.NoError(t, err)
	require.Equal(t, 1, report.Completed)
	issued, err := store.GetTicket(context.Background(), "ticket-paid")
	require.NoError(t, err)
	require.Equal(t, StateIssued, issued.State)
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

// TestTerminalTransitionsReleaseSeat is the FE-4 regression: refund and void
// hand the seat back to the trip in the same transition, the release is
// idempotent (a terminal ticket cannot transition again), and availability is
// restored for new buyers.
func TestTerminalTransitionsReleaseSeat(t *testing.T) {
	service, store, _ := seededService(t)
	// Fill the trip (capacity 2).
	first, err := service.Purchase(context.Background(), purchaseRequest("key-1"))
	require.NoError(t, err)
	_, err = service.Purchase(context.Background(), purchaseRequest("key-2"))
	require.NoError(t, err)
	_, err = service.Purchase(context.Background(), purchaseRequest("key-3"))
	require.ErrorIs(t, err, ErrCapacityExceeded)
	require.Equal(t, 2, store.trips["trip-1"].SeatsReserved)

	// Refund restores availability exactly once.
	_, err = service.Refund(context.Background(), first.TicketID, "subject-1", "passenger", "corr-r1")
	require.NoError(t, err)
	require.Equal(t, 1, store.trips["trip-1"].SeatsReserved, "refund releases the seat")
	_, err = service.Refund(context.Background(), first.TicketID, "subject-1", "passenger", "corr-r2")
	require.ErrorIs(t, err, ErrInvalidTransition)
	require.Equal(t, 1, store.trips["trip-1"].SeatsReserved, "no double release on the rejected retry")

	// Void restores availability too: a second RESERVED ticket fills the trip.
	reserved := Ticket{
		TicketID: "ticket-v", TripID: "trip-1", OperatorID: "op-1", State: StateReserved,
		Version: 1, LedgerReserveID: "reserve-ticket-v", FareNGNMinor: 250000,
		PurchaserPrincipal: "subject-1", Channel: ChannelDirect, PassengerDigest: "digest",
	}
	trip := store.trips["trip-1"]
	trip.SeatsReserved++
	store.trips["trip-1"] = trip
	store.tickets[reserved.TicketID] = reserved
	require.Equal(t, 2, store.trips["trip-1"].SeatsReserved, "trip full again")
	_, err = service.Purchase(context.Background(), purchaseRequest("key-4"))
	require.ErrorIs(t, err, ErrCapacityExceeded)
	_, err = service.Void(context.Background(), reserved.TicketID, "corr-void")
	require.NoError(t, err)
	require.Equal(t, 1, store.trips["trip-1"].SeatsReserved, "void releases the seat")
	_, err = service.Void(context.Background(), reserved.TicketID, "corr-void-2")
	require.ErrorIs(t, err, ErrInvalidTransition, "void of a terminal ticket fails closed")
	require.Equal(t, 1, store.trips["trip-1"].SeatsReserved, "no double release")

	// The freed seats are purchasable again.
	second, err := service.Purchase(context.Background(), purchaseRequest("key-4"))
	require.NoError(t, err)
	require.Equal(t, StateIssued, second.State)
	require.Equal(t, 2, store.trips["trip-1"].SeatsReserved)
}
