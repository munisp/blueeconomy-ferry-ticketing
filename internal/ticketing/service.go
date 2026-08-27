package ticketing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// traceTicketTransition annotates the active request span (when any) with the
// approved booking state transition. With the no-op tracer this is a no-op.
func traceTicketTransition(ctx context.Context, ticket Ticket, to State) {
	trace.SpanFromContext(ctx).SetAttributes(
		attribute.String("ferry.ticket_id", ticket.TicketID),
		attribute.String("ferry.ticket.transition.from", string(ticket.State)),
		attribute.String("ferry.ticket.transition.to", string(to)),
	)
}

// Event is one transactional-outbox record written atomically with the domain
// change that produced it.
type Event struct {
	EventID       string
	Topic         string
	SubjectID     string
	EventType     string
	Payload       map[string]any
	CorrelationID string
}

// Topic assignments (allowlist; the publisher fails closed on anything else).
const (
	TopicTicketing = "ferries.ticketing.v1"
	TopicManifest  = "ferries.manifest.v1"
)

// Outbox event types produced by this service.
const (
	EventTicketReserved   = "ferry.ticket.reserved"
	EventTicketPaid       = "ferry.ticket.paid"
	EventTicketIssued     = "ferry.ticket.issued"
	EventTicketRefunded   = "ferry.ticket.refunded"
	EventTicketExpired    = "ferry.ticket.expired"
	EventTicketVoided     = "ferry.ticket.voided"
	EventAgentCashIn      = "ferry.agent.cash_in_recorded"
	EventManifestExported = "ferry.manifest.exported"
	// EventManifestIncomplete audits a departure without a manifest.
	EventManifestIncomplete = "ferry.manifest.incomplete"
	EventAdverseWeather     = "ferry.adverse_weather.alerted"
)

// Ledger is the TigerBeetle boundary. Implementations are fail-closed: an
// unconfigured ledger is a construction error, never a silent skip.
type Ledger interface {
	// Reserve creates the two-phase pending transfer debiting the buyer
	// (or the agent float account) and returns its transfer ID.
	Reserve(ctx context.Context, ticketID string, channel Channel, amountNGNMinor int64) (string, error)
	// Post settles a pending reserve transfer and returns the post ID.
	Post(ctx context.Context, reserveTransferID string) (string, error)
	// Void releases a pending reserve transfer (purchase abandoned).
	Void(ctx context.Context, reserveTransferID string) error
	// Refund moves the fare back from operator revenue to the clearing
	// account and returns the refund transfer ID.
	Refund(ctx context.Context, ticketID string, amountNGNMinor int64) (string, error)
}

// Store is the persistence boundary. PostgreSQL is the production
// implementation; tests substitute in-memory fakes. Every mutating method is
// transactional and writes its outbox events in the same transaction.
type Store interface {
	// ReserveSeat atomically enforces capacity (no overbooking), persists the
	// RESERVED ticket, binds the idempotency key and records the outbox event.
	// replayed is true when the idempotency key already resolved to a ticket.
	ReserveSeat(ctx context.Context, ticket Ticket, idempotencyKey string, event Event) (replayed *Ticket, err error)
	GetTicket(ctx context.Context, ticketID string) (Ticket, error)
	// MarkPaid transitions RESERVED -> PAID, records the ledger post and, for
	// the agent channel, the cash-in ledger event, all in one transaction.
	MarkPaid(ctx context.Context, ticketID string, version int64, ledgerPostID string, cashIn *CashIn, events []Event) (Ticket, error)
	// MarkIssued transitions PAID -> ISSUED with a seat assignment.
	MarkIssued(ctx context.Context, ticketID string, version int64, seatNumber int, event Event) (Ticket, error)
	// Transition applies one approved terminal transition (REFUNDED, EXPIRED,
	// VOID) with optimistic concurrency and the outbox event.
	Transition(ctx context.Context, ticketID string, version int64, to State, event Event) (Ticket, error)
	GetTrip(ctx context.Context, tripID string) (Trip, error)
}

// CashIn is the agent cash-in ledger event.
type CashIn struct {
	CashInID         string
	AgentID          string
	AmountNGNMinor   int64
	LedgerTransferID string
}

// Service orchestrates purchase, payment, issue and refund.
type Service struct {
	store  Store
	ledger Ledger
	salt   string
	now    func() time.Time
}

// NewService fails closed on any missing dependency.
func NewService(store Store, ledger Ledger, manifestSalt string) (*Service, error) {
	if store == nil {
		return nil, errors.New("ticket store is required")
	}
	if ledger == nil {
		return nil, errors.New("ledger is required (fail-closed: purchases cannot run without TigerBeetle)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	return &Service{store: store, ledger: ledger, salt: manifestSalt, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Purchase reserves a seat (capacity enforced in the store transaction),
// reserves the fare on the ledger, settles it (cash-in ledger event for the
// agent channel) and issues the ticket. Replay of the same idempotency key
// returns the original ticket.
func (service *Service) Purchase(ctx context.Context, request PurchaseRequest) (Ticket, error) {
	if err := request.Validate(); err != nil {
		return Ticket{}, err
	}
	trip, err := service.store.GetTrip(ctx, request.TripID)
	if err != nil {
		return Ticket{}, fmt.Errorf("load trip: %w", err)
	}
	if trip.Status != "SCHEDULED" {
		return Ticket{}, fmt.Errorf("trip %s is not open for purchase (status %s)", trip.TripID, trip.Status)
	}
	if trip.ScheduledDeparture.Before(service.now()) {
		return Ticket{}, errors.New("trip has already departed")
	}
	digest, err := PassengerDigest(service.salt, request.PassengerRef)
	if err != nil {
		return Ticket{}, err
	}
	ticket := Ticket{
		TicketID:           uuid.NewString(),
		TripID:             trip.TripID,
		OperatorID:         trip.OperatorID,
		PassengerDigest:    digest,
		FareNGNMinor:       trip.FareNGNMinor,
		Channel:            request.Channel,
		State:              StateReserved,
		Version:            1,
		AgentID:            request.AgentID,
		PurchaserPrincipal: request.Principal,
		CorrelationID:      request.CorrelationID,
	}
	reserveID, err := service.ledger.Reserve(ctx, ticket.TicketID, request.Channel, ticket.FareNGNMinor)
	if err != nil {
		return Ticket{}, fmt.Errorf("reserve fare on ledger: %w", err)
	}
	ticket.LedgerReserveID = reserveID
	reservedEvent := service.event(EventTicketReserved, ticket, map[string]any{
		"channel": string(request.Channel),
	})
	replayed, err := service.store.ReserveSeat(ctx, ticket, request.IdempotencyKey, reservedEvent)
	if err != nil {
		// Compensate the ledger reserve; the purchase never happened.
		if voidErr := service.ledger.Void(ctx, reserveID); voidErr != nil {
			return Ticket{}, fmt.Errorf("reserve seat: %w; ledger void compensation also failed: %v", err, voidErr)
		}
		return Ticket{}, fmt.Errorf("reserve seat: %w", err)
	}
	if replayed != nil {
		// Idempotent replay: the original purchase already reserved the fare.
		if err := service.ledger.Void(ctx, reserveID); err != nil {
			return Ticket{}, fmt.Errorf("void duplicate ledger reserve: %w", err)
		}
		return *replayed, nil
	}

	postID, err := service.ledger.Post(ctx, reserveID)
	if err != nil {
		return Ticket{}, fmt.Errorf("settle fare on ledger: %w", err)
	}
	events := []Event{service.event(EventTicketPaid, ticket, map[string]any{"ledger_transfer_id": postID})}
	var cashIn *CashIn
	if request.Channel == ChannelAgentCashIn {
		cashIn = &CashIn{
			CashInID:         uuid.NewString(),
			AgentID:          request.AgentID,
			AmountNGNMinor:   ticket.FareNGNMinor,
			LedgerTransferID: postID,
		}
		events = append(events, service.event(EventAgentCashIn, ticket, map[string]any{
			"cash_in_id":         cashIn.CashInID,
			"agent_id":           request.AgentID,
			"amount_ngn_minor":   ticket.FareNGNMinor,
			"ledger_transfer_id": postID,
		}))
	}
	paid, err := service.store.MarkPaid(ctx, ticket.TicketID, 1, postID, cashIn, events)
	if err != nil {
		return Ticket{}, fmt.Errorf("mark ticket paid: %w", err)
	}
	ticket = paid

	issued, err := service.store.MarkIssued(ctx, ticket.TicketID, ticket.Version, ticket.SeatNumberValue(), service.event(EventTicketIssued, ticket, map[string]any{
		"voyage_reference":        trip.TripID,
		"route_reference":         trip.RouteReference,
		"payment_reference":       ticket.LedgerPostID,
		"passenger_digest_sha256": ticket.PassengerDigest,
		"fare_ngn_minor":          ticket.FareNGNMinor,
		"issued_at":               service.now().Format(time.RFC3339),
	}))
	if err != nil {
		return Ticket{}, fmt.Errorf("issue ticket: %w", err)
	}
	return issued, nil
}

// SeatNumberValue exposes the seat assigned at reservation time (the store
// assigns seats sequentially under the capacity lock).
func (ticket Ticket) SeatNumberValue() int {
	if ticket.SeatNumber == nil {
		return 0
	}
	return *ticket.SeatNumber
}

// Refund returns the fare and moves the ticket to REFUNDED.
func (service *Service) Refund(ctx context.Context, ticketID, principal, principalRole, correlationID string) (Ticket, error) {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if !ValidTransition(ticket.State, StateRefunded) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, StateRefunded)
	}
	traceTicketTransition(ctx, ticket, StateRefunded)
	refundID, err := service.ledger.Refund(ctx, ticket.TicketID, ticket.FareNGNMinor)
	if err != nil {
		return Ticket{}, fmt.Errorf("refund fare on ledger: %w", err)
	}
	return service.store.Transition(ctx, ticketID, ticket.Version, StateRefunded, Event{
		EventID:       uuid.NewString(),
		Topic:         TopicTicketing,
		SubjectID:     ticket.TicketID,
		EventType:     EventTicketRefunded,
		CorrelationID: correlationID,
		Payload: map[string]any{
			"ticket_id":          ticket.TicketID,
			"principal_id":       principal,
			"principal_role":     principalRole,
			"ledger_transfer_id": refundID,
			"state":              string(StateRefunded),
		},
	})
}

// Expire moves a ticket to EXPIRED (reservation/payment window elapsed or the
// trip departed unboarded). No ledger movement: expired RESERVED tickets were
// voided on the ledger by the pending-transfer timeout; PAID/ISSUED expiry is
// an operator policy decision reconciled separately.
func (service *Service) Expire(ctx context.Context, ticketID, correlationID string) (Ticket, error) {
	return service.terminal(ctx, ticketID, StateExpired, EventTicketExpired, correlationID)
}

// Void cancels a ticket without a ledger refund (void before settlement).
func (service *Service) Void(ctx context.Context, ticketID, correlationID string) (Ticket, error) {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if ticket.State == StateReserved && ticket.LedgerReserveID != "" {
		if err := service.ledger.Void(ctx, ticket.LedgerReserveID); err != nil {
			return Ticket{}, fmt.Errorf("void pending ledger reserve: %w", err)
		}
	}
	return service.terminal(ctx, ticketID, StateVoid, EventTicketVoided, correlationID)
}

func (service *Service) terminal(ctx context.Context, ticketID string, to State, eventType, correlationID string) (Ticket, error) {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if !ValidTransition(ticket.State, to) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, to)
	}
	traceTicketTransition(ctx, ticket, to)
	return service.store.Transition(ctx, ticketID, ticket.Version, to, Event{
		EventID:       uuid.NewString(),
		Topic:         TopicTicketing,
		SubjectID:     ticket.TicketID,
		EventType:     eventType,
		CorrelationID: correlationID,
		Payload: map[string]any{
			"ticket_id":    ticket.TicketID,
			"principal_id": ticket.PurchaserPrincipal,
			"state":        string(to),
		},
	})
}

func (service *Service) event(eventType string, ticket Ticket, extra map[string]any) Event {
	payload := map[string]any{
		"ticket_id":    ticket.TicketID,
		"trip_id":      ticket.TripID,
		"operator_id":  ticket.OperatorID,
		"principal_id": ticket.PurchaserPrincipal,
		"state":        string(ticket.State),
	}
	for key, value := range extra {
		payload[key] = value
	}
	return Event{
		EventID:       uuid.NewString(),
		Topic:         TopicTicketing,
		SubjectID:     ticket.TicketID,
		EventType:     eventType,
		CorrelationID: ticket.CorrelationID,
		Payload:       payload,
	}
}
