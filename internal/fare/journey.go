package fare

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// TicketStore is the seat-ticket persistence boundary the journey saga
// composes (implemented by ticketing.PostgresStore).
type TicketStore interface {
	ReserveSeat(ctx context.Context, ticket ticketing.Ticket, idempotencyKey string, event ticketing.Event) (replayed *ticketing.Ticket, err error)
	GetTicket(ctx context.Context, ticketID string) (ticketing.Ticket, error)
	MarkPaid(ctx context.Context, ticketID string, version int64, ledgerPostID string, cashIn *ticketing.CashIn, events []ticketing.Event) (ticketing.Ticket, error)
	MarkIssued(ctx context.Context, ticketID string, version int64, seatNumber int, event ticketing.Event) (ticketing.Ticket, error)
	GetTrip(ctx context.Context, tripID string) (ticketing.Trip, error)
}

// JourneyPurchaseRequest carries one capped single-journey purchase. With
// ChannelAccount the fare is debited from the BlueFare account (and the cap
// is keyed to that account — caps count journeys on the same account, never
// the instrument, per the TfL design rule).
type JourneyPurchaseRequest struct {
	TripID         string
	PassengerRef   string
	Channel        string
	AgentID        string
	AccountID      string
	IdempotencyKey string
	CorrelationID  string
	Principal      string
	PrincipalRole  string
}

// Validate fails closed on any malformed request.
func (request JourneyPurchaseRequest) Validate() error {
	if strings.TrimSpace(request.TripID) == "" {
		return errors.New("trip_id is required")
	}
	if strings.TrimSpace(request.PassengerRef) == "" || len(request.PassengerRef) > 256 {
		return errors.New("passenger reference is required")
	}
	switch request.Channel {
	case ChannelDirect:
	case ChannelAgentCashIn:
		if strings.TrimSpace(request.AgentID) == "" {
			return errors.New("agent_id is required for agent cash-in purchases")
		}
	case ChannelAccount:
		if strings.TrimSpace(request.AccountID) == "" {
			return errors.New("account_id is required for account journeys")
		}
	default:
		return fmt.Errorf("channel %q is not supported", request.Channel)
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 128 {
		return errors.New("idempotency key is required")
	}
	if strings.TrimSpace(request.CorrelationID) == "" || strings.TrimSpace(request.Principal) == "" {
		return errors.New("correlation id and purchaser principal are required")
	}
	return nil
}

// JourneyService prices and books single journeys. It reuses the ticket
// booking spine verbatim — seat capacity in the store transaction, two-phase
// ledger reserve/post, durable idempotency keys, outbox events — with the
// cap engine's atomic pricing decision as the fare. Fully capped journeys
// issue valid zero-fare tickets (no ledger movement: nothing is charged).
type JourneyService struct {
	tickets  TicketStore
	fare     *PostgresStore
	ledger   ticketing.Ledger
	accounts AccountLedger
	salt     string
	now      func() time.Time
}

// NewJourneyService fails closed on any missing dependency.
func NewJourneyService(tickets TicketStore, fare *PostgresStore, ledgerSvc ticketing.Ledger, accounts AccountLedger, manifestSalt string) (*JourneyService, error) {
	if tickets == nil || fare == nil {
		return nil, errors.New("ticket store and fare store are required")
	}
	if ledgerSvc == nil || accounts == nil {
		return nil, errors.New("ledgers are required (fail-closed)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	return &JourneyService{tickets: tickets, fare: fare, ledger: ledgerSvc, accounts: accounts, salt: manifestSalt,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// Purchase prices the journey (concession -> transfer window -> caps, one
// atomic decision) and books the seat through the standard saga. Replay of
// the same idempotency key returns the original ticket; the pricing decision
// is never applied twice for one key.
func (service *JourneyService) Purchase(ctx context.Context, request JourneyPurchaseRequest) (ticketing.Ticket, CapJourney, error) {
	if err := request.Validate(); err != nil {
		return ticketing.Ticket{}, CapJourney{}, err
	}
	trip, err := service.tickets.GetTrip(ctx, request.TripID)
	if err != nil {
		return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("load trip: %w", err)
	}
	if trip.Status != "SCHEDULED" {
		return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("trip %s is not open for purchase (status %s)", trip.TripID, trip.Status)
	}
	if trip.ScheduledDeparture.Before(service.now()) {
		return ticketing.Ticket{}, CapJourney{}, errors.New("trip has already departed")
	}
	digest, err := ticketing.PassengerDigest(service.salt, request.PassengerRef)
	if err != nil {
		return ticketing.Ticket{}, CapJourney{}, err
	}
	// Idempotent replay resolves BEFORE pricing (no double spend, no double
	// seat, no double charge).
	if existing, err := service.findTicketByIdempotency(ctx, request.IdempotencyKey); err == nil {
		if existing.PurchaserPrincipal != request.Principal {
			return ticketing.Ticket{}, CapJourney{}, ErrIdempotencyConflict
		}
		journey, _ := service.fare.GetCapJourney(ctx, journeyIDFor(request.IdempotencyKey))
		ticket, err := service.complete(ctx, *existing, trip, request.Channel, "")
		return ticket, journey, err
	} else if !errors.Is(err, ErrNotFound) && !errors.Is(err, ticketing.ErrNotFound) {
		return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("resolve idempotency key: %w", err)
	}
	subjectRef := digest
	concessionClass := ConcessionStandard
	var account FareAccount
	if request.Channel == ChannelAccount {
		account, err = service.fare.GetFareAccount(ctx, request.AccountID)
		if err != nil {
			return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("load fare account: %w", err)
		}
		if account.Status != "ACTIVE" {
			return ticketing.Ticket{}, CapJourney{}, ErrAccountNotActive
		}
		subjectRef = account.AccountID
		concessionClass = account.ConcessionClass
	}
	journeyID := journeyIDFor(request.IdempotencyKey)
	journey, err := service.fare.PriceJourney(ctx, PriceInput{
		JourneyID:         journeyID,
		SubjectRef:        subjectRef,
		AccountID:         request.AccountID,
		TripID:            trip.TripID,
		RouteReference:    trip.RouteReference,
		OperatorID:        trip.OperatorID,
		StandardFareMinor: trip.FareNGNMinor,
		ConcessionClass:   concessionClass,
		Now:               service.now(),
	}, service.event(EventCapJourneyPriced, journeyID, request.CorrelationID, map[string]any{
		"journey_id":       journeyID,
		"subject_ref":      subjectRef,
		"trip_id":          trip.TripID,
		"route_reference":  trip.RouteReference,
		"operator_id":      trip.OperatorID,
		"standard_fare_minor": trip.FareNGNMinor,
		"principal_id":     request.Principal,
	}))
	if err != nil {
		return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("price journey: %w", err)
	}
	ticket, err := service.bookPriced(ctx, request, trip, digest, journey, account)
	if err != nil {
		// Saga compensation: return the spend so a failed purchase never
		// consumes cap allowance.
		if reverseErr := service.fare.ReverseJourney(ctx, journey.JourneyID, service.event(EventCapJourneyReversed, journey.JourneyID, request.CorrelationID, map[string]any{
			"journey_id": journey.JourneyID, "reason": "purchase_failed",
		})); reverseErr != nil {
			return ticketing.Ticket{}, CapJourney{}, fmt.Errorf("book journey: %w; cap reversal also failed: %v", err, reverseErr)
		}
		return ticketing.Ticket{}, CapJourney{}, err
	}
	if err := service.fare.AttachTicket(ctx, journey.JourneyID, ticket.TicketID); err != nil {
		// Informational linkage only; never masks a successful purchase.
		_ = err
	}
	journey.TicketID = ticket.TicketID
	return ticket, journey, nil
}

// journeyIDFor derives the deterministic pricing-decision id from the
// purchase idempotency key, so one key prices exactly once.
func journeyIDFor(idempotencyKey string) string {
	return "jny-" + idempotencyKey
}

// bookPriced runs the seat booking saga at the priced charge.
func (service *JourneyService) bookPriced(ctx context.Context, request JourneyPurchaseRequest, trip ticketing.Trip, digest string, journey CapJourney, account FareAccount) (ticketing.Ticket, error) {
	ticket := ticketing.Ticket{
		TicketID:           uuid.NewString(),
		TripID:             trip.TripID,
		OperatorID:         trip.OperatorID,
		PassengerDigest:    digest,
		FareNGNMinor:       journey.ChargedMinor,
		Channel:            ticketing.Channel(request.Channel),
		State:              ticketing.StateReserved,
		Version:            1,
		AgentID:            request.AgentID,
		PurchaserPrincipal: request.Principal,
		CorrelationID:      request.CorrelationID,
	}
	reserveID := ""
	var err error
	if journey.ChargedMinor > 0 {
		if request.Channel == ChannelAccount {
			reserveID, err = service.accounts.ReserveFromAccount(ctx, ticket.TicketID, account.LedgerAccountID, journey.ChargedMinor)
		} else {
			reserveID, err = service.ledger.Reserve(ctx, ticket.TicketID, ticketing.Channel(request.Channel), journey.ChargedMinor)
		}
		if err != nil {
			return ticketing.Ticket{}, fmt.Errorf("reserve fare on ledger: %w", err)
		}
	}
	ticket.LedgerReserveID = reserveID
	reservedEvent := service.event(ticketing.EventTicketReserved, ticket.TicketID, ticket.CorrelationID, map[string]any{
		"ticket_id":     ticket.TicketID,
		"trip_id":       trip.TripID,
		"operator_id":   trip.OperatorID,
		"principal_id":  ticket.PurchaserPrincipal,
		"channel":       request.Channel,
		"pricing_class": journey.PricingClass,
		"journey_id":    journey.JourneyID,
		"state":         string(ticketing.StateReserved),
	})
	replayed, err := service.tickets.ReserveSeat(ctx, ticket, request.IdempotencyKey, reservedEvent)
	if err != nil {
		if reserveID != "" {
			if voidErr := service.ledger.Void(ctx, reserveID); voidErr != nil {
				return ticketing.Ticket{}, fmt.Errorf("reserve seat: %w; ledger void compensation also failed: %v", err, voidErr)
			}
		}
		return ticketing.Ticket{}, fmt.Errorf("reserve seat: %w", err)
	}
	if replayed != nil {
		// Concurrent twin won the idempotency key: void the duplicate reserve
		// and resume the original.
		if reserveID != "" {
			if err := service.ledger.Void(ctx, reserveID); err != nil {
				return ticketing.Ticket{}, fmt.Errorf("void duplicate ledger reserve: %w", err)
			}
		}
		return service.complete(ctx, *replayed, trip, request.Channel, request.AccountID)
	}
	return service.complete(ctx, ticket, trip, request.Channel, request.AccountID)
}

// complete drives a RESERVED or PAID ticket through settlement and issuance
// (mirrors the ticket saga's shared tail; a zero-fare cap ticket has no
// reserve to post and settles as CAP_COVERED).
func (service *JourneyService) complete(ctx context.Context, ticket ticketing.Ticket, trip ticketing.Trip, channel, accountID string) (ticketing.Ticket, error) {
	var err error
	if ticket.State == ticketing.StateReserved {
		postID := ""
		if ticket.LedgerReserveID != "" {
			postID, err = service.ledger.Post(ctx, ticket.LedgerReserveID)
			if err != nil {
				return ticketing.Ticket{}, fmt.Errorf("settle fare on ledger: %w", err)
			}
		}
		events := []ticketing.Event{service.event(ticketing.EventTicketPaid, ticket.TicketID, ticket.CorrelationID, map[string]any{
			"ticket_id":          ticket.TicketID,
			"trip_id":            ticket.TripID,
			"operator_id":        ticket.OperatorID,
			"principal_id":       ticket.PurchaserPrincipal,
			"ledger_transfer_id": postID,
			"channel":            channel,
			"state":              string(ticketing.StatePaid),
		})}
		var cashIn *ticketing.CashIn
		if channel == ChannelAgentCashIn && ticket.FareNGNMinor > 0 {
			cashIn = &ticketing.CashIn{
				CashInID:         uuid.NewString(),
				AgentID:          ticket.AgentID,
				AmountNGNMinor:   ticket.FareNGNMinor,
				LedgerTransferID: postID,
			}
		}
		ticket, err = service.tickets.MarkPaid(ctx, ticket.TicketID, ticket.Version, postID, cashIn, events)
		if err != nil {
			return ticketing.Ticket{}, fmt.Errorf("mark ticket paid: %w", err)
		}
		if channel == ChannelAccount {
			if err := service.adjustBalanceCache(ctx, accountID, -ticket.FareNGNMinor); err != nil {
				return ticketing.Ticket{}, fmt.Errorf("update balance cache: %w", err)
			}
		}
	}
	if ticket.State == ticketing.StatePaid {
		ticket, err = service.tickets.MarkIssued(ctx, ticket.TicketID, ticket.Version, ticket.SeatNumberValue(), service.event(ticketing.EventTicketIssued, ticket.TicketID, ticket.CorrelationID, map[string]any{
			"ticket_id":    ticket.TicketID,
			"trip_id":      ticket.TripID,
			"operator_id":  ticket.OperatorID,
			"principal_id": ticket.PurchaserPrincipal,
			"state":        string(ticketing.StateIssued),
		}))
		if err != nil {
			return ticketing.Ticket{}, fmt.Errorf("issue ticket: %w", err)
		}
	}
	if ticket.State != ticketing.StateIssued {
		return ticketing.Ticket{}, fmt.Errorf("%w: cannot complete ticket in state %s", ErrInvalidTransition, ticket.State)
	}
	return ticket, nil
}

// findTicketByIdempotency resolves the durable purchase binding.
func (service *JourneyService) findTicketByIdempotency(ctx context.Context, key string) (*ticketing.Ticket, error) {
	var ticketID string
	err := service.fare.Pool().QueryRow(ctx,
		`SELECT ticket_id FROM purchase_idempotency WHERE idempotency_key = $1`, key).Scan(&ticketID)
	if err != nil {
		return nil, ErrNotFound
	}
	ticket, err := service.tickets.GetTicket(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	return &ticket, nil
}

func (service *JourneyService) adjustBalanceCache(ctx context.Context, accountID string, delta int64) error {
	tx, err := service.fare.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := service.fare.AdjustCachedBalance(ctx, tx, accountID, delta); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (service *JourneyService) event(eventType, subjectID, correlationID string, payload map[string]any) ticketing.Event {
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	return ticketing.Event{
		EventID:       uuid.NewString(),
		Topic:         TopicFare,
		SubjectID:     subjectID,
		EventType:     eventType,
		CorrelationID: correlationID,
		Payload:       payload,
	}
}
