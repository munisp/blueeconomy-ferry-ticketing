package ticketing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns the package tracer. With telemetry disabled (no OTLP
// endpoint) the global provider is a no-op and every span is non-recording —
// telemetry never gates the business path.
func tracer() trace.Tracer {
	return otel.Tracer("github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing")
}

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
	EventTicketReserved = "ferry.ticket.reserved"
	EventTicketPaid     = "ferry.ticket.paid"
	EventTicketIssued   = "ferry.ticket.issued"
	EventTicketRefunded = "ferry.ticket.refunded"
	EventTicketExpired  = "ferry.ticket.expired"
	EventTicketVoided   = "ferry.ticket.voided"
	EventAgentCashIn    = "ferry.agent.cash_in_recorded"
	// EventTripCancelled audits the operator-initiated trip cancellation.
	EventTripCancelled = "ferry.trip.cancelled"
	// EventVoidApprovalRequested audits the maker half of a dual-control
	// void: the first officer's request a second officer must confirm.
	EventVoidApprovalRequested = "ferry.ticket.void_approval_requested"
	EventManifestExported      = "ferry.manifest.exported"
	// EventManifestIncomplete audits a departure without a manifest.
	EventManifestIncomplete = "ferry.manifest.incomplete"
	EventAdverseWeather     = "ferry.adverse_weather.alerted"
)

// ReserveStatus is the reconciled state of a pending ledger reserve, resolved
// from TigerBeetle transfer lookups (never guessed from local state).
type ReserveStatus string

const (
	// ReserveStatusUnknown means the reserve transfer does not exist.
	ReserveStatusUnknown ReserveStatus = "UNKNOWN"
	// ReserveStatusPending means the two-phase reserve is still open.
	ReserveStatusPending ReserveStatus = "PENDING"
	// ReserveStatusPosted means the reserve was settled (irreversible).
	ReserveStatusPosted ReserveStatus = "POSTED"
	// ReserveStatusReleased means the reserve was voided or auto-voided by
	// the pending-transfer timeout; the buyer was never charged.
	ReserveStatusReleased ReserveStatus = "RELEASED"
)

// ReserveResolution is the outcome of resolving one reserve transfer.
type ReserveResolution struct {
	Status ReserveStatus
	// PostTransferID is the deterministic post transfer ID when the reserve
	// was settled; empty otherwise.
	PostTransferID string
}

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
	// ResolveReserve reports the authoritative state of one reserve transfer
	// so the reconciler can converge ticket state with money state.
	ResolveReserve(ctx context.Context, reserveTransferID string) (ReserveResolution, error)
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
	// GetVoidApproval returns the pending (unconsumed) dual-control void
	// approval for a ticket, ErrNotFound when none exists.
	GetVoidApproval(ctx context.Context, ticketID string) (VoidApproval, error)
	// RequestVoidApproval records the maker half of a dual-control void with
	// its audit event in one transaction.
	RequestVoidApproval(ctx context.Context, approval VoidApproval, event Event) error
	// ConsumeVoidApproval marks the pending approval spent by the confirming
	// (checker) officer; it fails when no pending approval exists.
	ConsumeVoidApproval(ctx context.Context, ticketID, confirmedBy string) error
	// ListReservedBefore returns up to limit RESERVED tickets created before
	// cutoff, oldest first (reconciler sweep input).
	ListReservedBefore(ctx context.Context, cutoff time.Time, limit int) ([]Ticket, error)
	// ListUnissuedPaidBefore returns up to limit PAID (not yet ISSUED)
	// tickets last updated before cutoff, oldest first (reconciler sweep
	// input for purchases interrupted between payment and issuance).
	ListUnissuedPaidBefore(ctx context.Context, cutoff time.Time, limit int) ([]Ticket, error)
}

// CashIn is the agent cash-in ledger event.
type CashIn struct {
	CashInID         string
	AgentID          string
	AmountNGNMinor   int64
	LedgerTransferID string
}

// VoidApproval is the maker-checker record for voiding one sold ticket: the
// requesting (maker) officer, the fare at stake, and — once spent — the
// confirming (checker) officer.
type VoidApproval struct {
	TicketID       string
	RequestedBy    string
	AmountNGNMinor int64
	CorrelationID  string
	CreatedAt      time.Time
}

// ServiceOption tunes optional service behaviour. Money-path knobs fail
// closed by default and only relax via explicit configuration.
type ServiceOption func(*Service) error

// WithVoidDualControlThreshold sets the fare (NGN minor units) at or above
// which voiding a sold ticket requires a second officer's confirmation. The
// default is 0: every PAID/ISSUED void requires dual control unless the
// operator explicitly relaxes the threshold.
func WithVoidDualControlThreshold(thresholdNGNMinor int64) ServiceOption {
	return func(service *Service) error {
		if thresholdNGNMinor < 0 {
			return errors.New("void dual-control threshold must be non-negative")
		}
		service.voidDualControlThreshold = thresholdNGNMinor
		return nil
	}
}

// Service orchestrates purchase, payment, issue and refund.
type Service struct {
	store  Store
	ledger Ledger
	salt   string
	now    func() time.Time
	// voidDualControlThreshold is the fare (NGN minor) at or above which a
	// sold-ticket void requires a second officer (maker-checker). Default 0:
	// dual control for every sold-ticket void.
	voidDualControlThreshold int64
}

// NewService fails closed on any missing dependency.
func NewService(store Store, ledger Ledger, manifestSalt string, options ...ServiceOption) (*Service, error) {
	if store == nil {
		return nil, errors.New("ticket store is required")
	}
	if ledger == nil {
		return nil, errors.New("ledger is required (fail-closed: purchases cannot run without TigerBeetle)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	service := &Service{store: store, ledger: ledger, salt: manifestSalt, now: func() time.Time { return time.Now().UTC() }}
	for _, option := range options {
		if err := option(service); err != nil {
			return nil, err
		}
	}
	return service, nil
}

// Purchase reserves a seat (capacity enforced in the store transaction),
// reserves the fare on the ledger, settles it (cash-in ledger event for the
// agent channel) and issues the ticket. Replay of the same idempotency key
// returns the original ticket.
func (service *Service) Purchase(ctx context.Context, request PurchaseRequest) (Ticket, error) {
	// Booking saga span: RESERVED → PAID → ISSUED (or the idempotent-replay
	// tail). Ledger and store child spans carry their own failure detail; the
	// transition attributes land on this span via traceTicketTransition.
	ctx, span := tracer().Start(ctx, "ferry.booking.purchase_saga",
		trace.WithAttributes(
			attribute.String("ferry.trip_id", request.TripID),
			attribute.String("ferry.channel", string(request.Channel)),
		))
	defer span.End()
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
		// Void the duplicate reserve created above, then resume the saga from
		// the stored ticket state so a previously interrupted purchase (post
		// or MarkPaid/MarkIssued failure) converges instead of being stranded.
		if err := service.ledger.Void(ctx, reserveID); err != nil {
			return Ticket{}, fmt.Errorf("void duplicate ledger reserve: %w", err)
		}
		switch replayed.State {
		case StateIssued:
			return *replayed, nil
		case StateReserved, StatePaid:
			return service.complete(ctx, *replayed, trip)
		default:
			return Ticket{}, fmt.Errorf("%w: idempotent replay resolved to terminal state %s", ErrInvalidTransition, replayed.State)
		}
	}
	return service.complete(ctx, ticket, trip)
}

// complete drives a RESERVED or PAID ticket through settlement and issuance.
// It is the shared tail of the purchase saga for the fresh path, the
// idempotent-replay path and the reconciler: every step is idempotent-safe
// (deterministic ledger transfer IDs deduplicate cluster-side; store
// transitions are optimistic-concurrency guarded).
func (service *Service) complete(ctx context.Context, ticket Ticket, trip Trip) (Ticket, error) {
	var err error
	if ticket.State == StateReserved {
		postID, err := service.ledger.Post(ctx, ticket.LedgerReserveID)
		if err != nil {
			return Ticket{}, fmt.Errorf("settle fare on ledger: %w", err)
		}
		ticket, err = service.markPaid(ctx, ticket, postID)
		if err != nil {
			return Ticket{}, err
		}
	}
	if ticket.State == StatePaid {
		ticket, err = service.issue(ctx, ticket, trip)
		if err != nil {
			return Ticket{}, err
		}
	}
	if ticket.State != StateIssued {
		return Ticket{}, fmt.Errorf("%w: cannot complete ticket in state %s", ErrInvalidTransition, ticket.State)
	}
	return ticket, nil
}

// markPaid records the settled fare: RESERVED -> PAID with the ledger post ID
// and, for the agent channel, the cash-in ledger event, in one transaction.
// A failure here after the ledger post leaves money and ticket state
// diverged; the reconciler (Reconcile) converges it, and an idempotent
// purchase retry resumes through complete.
func (service *Service) markPaid(ctx context.Context, ticket Ticket, postID string) (Ticket, error) {
	events := []Event{service.event(EventTicketPaid, ticket, map[string]any{"ledger_transfer_id": postID})}
	var cashIn *CashIn
	if ticket.Channel == ChannelAgentCashIn {
		cashIn = &CashIn{
			CashInID:         uuid.NewString(),
			AgentID:          ticket.AgentID,
			AmountNGNMinor:   ticket.FareNGNMinor,
			LedgerTransferID: postID,
		}
		events = append(events, service.event(EventAgentCashIn, ticket, map[string]any{
			"cash_in_id":         cashIn.CashInID,
			"agent_id":           ticket.AgentID,
			"amount_ngn_minor":   ticket.FareNGNMinor,
			"ledger_transfer_id": postID,
		}))
	}
	paid, err := service.store.MarkPaid(ctx, ticket.TicketID, ticket.Version, postID, cashIn, events)
	if err != nil {
		return Ticket{}, fmt.Errorf("mark ticket paid: %w", err)
	}
	return paid, nil
}

// issue assigns the seat and moves PAID -> ISSUED with the boarding event.
func (service *Service) issue(ctx context.Context, ticket Ticket, trip Trip) (Ticket, error) {
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

// Refund returns the fare and moves the ticket to REFUNDED. A ticket whose
// boarding was consumed (boarded_at set or embarked) can never be refunded:
// the passenger traveled and the fare is earned. The guard is mirrored by the
// tickets_block_boarded_refund database trigger so no code path bypasses it.
func (service *Service) Refund(ctx context.Context, ticketID, principal, principalRole, correlationID string) (Ticket, error) {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if !ValidTransition(ticket.State, StateRefunded) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, StateRefunded)
	}
	if ticket.BoardedAt != nil || ticket.Embarked {
		return Ticket{}, ErrTicketBoarded
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

// ReconcileReport summarizes one reconciler sweep.
type ReconcileReport struct {
	// Completed counts tickets driven forward (posted reserve -> PAID ->
	// ISSUED, or PAID -> ISSUED).
	Completed int
	// Expired counts RESERVED tickets whose reserve was released (voided or
	// auto-voided by the pending-transfer timeout) moved to EXPIRED.
	Expired int
	// Pending counts tickets whose reserve is still open or which are too
	// young for the configured ages; revisited by the next sweep.
	Pending int
	// Failed counts per-ticket errors; the sweep continues and the next run
	// retries them (every recovery step is idempotent-safe).
	Failed int
}

// Reconcile is the purchase-saga recovery sweep. It resolves each aged
// RESERVED ticket's reserve against TigerBeetle and converges money and
// ticket state:
//
//   - POSTED reserve + RESERVED ticket (MarkPaid failed after Post; the
//     ledger post is irreversible): the ticket is driven through payment and
//     issuance so the passenger receives what they were charged for.
//   - RELEASED reserve + RESERVED ticket (pending timeout auto-voided the
//     reserve; the passenger can never pay it): the ticket is expired and its
//     seat released.
//   - PENDING reserve: left for the TigerBeetle timeout and a later sweep.
//
// It also drives PAID-but-never-ISSUED tickets (interrupted between payment
// and issuance) to ISSUED. completionAge is the minimum ticket age before the
// reconciler completes a posted divergence; expiryAge is the minimum age
// before a released reservation expires (operator grace over the ledger
// pending timeout). Per-ticket failures never abort the sweep.
func (service *Service) Reconcile(ctx context.Context, completionAge, expiryAge time.Duration, limit int) (ReconcileReport, error) {
	if limit <= 0 {
		return ReconcileReport{}, errors.New("reconcile batch limit must be positive")
	}
	if completionAge < 0 || expiryAge < 0 {
		return ReconcileReport{}, errors.New("reconcile ages must be non-negative")
	}
	var report ReconcileReport
	now := service.now()
	sweepCutoff := now.Add(-completionAge)
	if expiryAge < completionAge {
		sweepCutoff = now.Add(-expiryAge)
	}
	stuck, err := service.store.ListReservedBefore(ctx, sweepCutoff, limit)
	if err != nil {
		return report, fmt.Errorf("list reserved tickets for reconciliation: %w", err)
	}
	for _, ticket := range stuck {
		age := now.Sub(ticket.CreatedAt)
		if ticket.LedgerReserveID == "" {
			// Fail closed: a RESERVED ticket without a reserve reference is
			// corrupt (the reserve always precedes the ticket row); never
			// guess its money state.
			report.Failed++
			continue
		}
		resolution, err := service.ledger.ResolveReserve(ctx, ticket.LedgerReserveID)
		if err != nil {
			report.Failed++
			continue
		}
		switch {
		case resolution.Status == ReserveStatusPosted && age >= completionAge:
			trip, err := service.store.GetTrip(ctx, ticket.TripID)
			if err != nil {
				report.Failed++
				continue
			}
			completed := ticket
			if resolution.PostTransferID != "" {
				// The reserve already settled cluster-side; skip a redundant
				// post and record the deterministic post transfer ID.
				completed, err = service.markPaid(ctx, ticket, resolution.PostTransferID)
			} else {
				completed, err = service.complete(ctx, ticket, trip)
			}
			if err != nil {
				report.Failed++
				continue
			}
			if completed.State == StatePaid {
				if _, err := service.issue(ctx, completed, trip); err != nil {
					report.Failed++
					continue
				}
			}
			report.Completed++
		case resolution.Status == ReserveStatusReleased && age >= expiryAge:
			if _, err := service.terminal(ctx, ticket.TicketID, StateExpired, EventTicketExpired, ticket.CorrelationID); err != nil {
				report.Failed++
				continue
			}
			report.Expired++
		default:
			report.Pending++
		}
	}
	// Purchases interrupted between payment and issuance (MarkIssued failed):
	// money is settled and the ticket is PAID; finish issuance.
	unissued, err := service.store.ListUnissuedPaidBefore(ctx, now.Add(-completionAge), limit)
	if err != nil {
		return report, fmt.Errorf("list paid tickets for reconciliation: %w", err)
	}
	for _, ticket := range unissued {
		trip, err := service.store.GetTrip(ctx, ticket.TripID)
		if err != nil {
			report.Failed++
			continue
		}
		if _, err := service.issue(ctx, ticket, trip); err != nil {
			report.Failed++
			continue
		}
		report.Completed++
	}
	return report, nil
}

// Void cancels a ticket. Money semantics by state, chosen so the fare can
// never sit in operator revenue without a corresponding refund entry:
//
//   - RESERVED (pre-settlement): the pending reserve is voided; the passenger
//     was never charged, so no refund transfer and no dual control.
//   - PAID/ISSUED (sold): the void issues the refund transfer (operator
//     revenue -> passenger clearing) in the same flow, and — at or above the
//     configured dual-control threshold — requires maker-checker: the first
//     officer records a void approval, a second, distinct officer confirms
//     it by re-issuing the void.
//
// A boarding-consumed ticket can never be voided (ErrTicketBoarded; the fare
// is earned), mirrored by the tickets_block_boarded_refund trigger.
func (service *Service) Void(ctx context.Context, ticketID, principal, principalRole, correlationID string) (Ticket, error) {
	if principal == "" {
		return Ticket{}, errors.New("void principal is required")
	}
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Ticket{}, err
	}
	if !ValidTransition(ticket.State, StateVoid) {
		return Ticket{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, ticket.State, StateVoid)
	}
	if ticket.BoardedAt != nil || ticket.Embarked {
		return Ticket{}, ErrTicketBoarded
	}
	traceTicketTransition(ctx, ticket, StateVoid)
	if ticket.State == StateReserved {
		if ticket.LedgerReserveID != "" {
			if err := service.ledger.Void(ctx, ticket.LedgerReserveID); err != nil {
				return Ticket{}, fmt.Errorf("void pending ledger reserve: %w", err)
			}
		}
		return service.voidTransition(ctx, ticket, "", principal, principalRole, correlationID)
	}

	// Sold ticket: dual control at or above the threshold.
	dualControl := ticket.FareNGNMinor >= service.voidDualControlThreshold
	if dualControl {
		approval, err := service.store.GetVoidApproval(ctx, ticketID)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				return Ticket{}, fmt.Errorf("load void approval: %w", err)
			}
			// Maker: record the request for a second officer to confirm.
			request := VoidApproval{
				TicketID:       ticketID,
				RequestedBy:    principal,
				AmountNGNMinor: ticket.FareNGNMinor,
				CorrelationID:  correlationID,
			}
			if err := service.store.RequestVoidApproval(ctx, request, Event{
				EventID:       uuid.NewString(),
				Topic:         TopicTicketing,
				SubjectID:     ticketID,
				EventType:     EventVoidApprovalRequested,
				CorrelationID: correlationID,
				Payload: map[string]any{
					"ticket_id":        ticketID,
					"principal_id":     principal,
					"principal_role":   principalRole,
					"amount_ngn_minor": ticket.FareNGNMinor,
				},
			}); err != nil {
				return Ticket{}, fmt.Errorf("record void approval request: %w", err)
			}
			return Ticket{}, ErrVoidApprovalRequired
		}
		if approval.RequestedBy == principal {
			// Maker-checker: the requesting officer can never self-approve.
			return Ticket{}, fmt.Errorf("%w: the requesting officer cannot self-approve", ErrVoidApprovalRequired)
		}
	}

	refundID, err := service.ledger.Refund(ctx, ticket.TicketID, ticket.FareNGNMinor)
	if err != nil {
		return Ticket{}, fmt.Errorf("refund fare on ledger: %w", err)
	}
	if dualControl {
		if err := service.store.ConsumeVoidApproval(ctx, ticketID, principal); err != nil {
			return Ticket{}, fmt.Errorf("consume void approval: %w", err)
		}
	}
	return service.voidTransition(ctx, ticket, refundID, principal, principalRole, correlationID)
}

// voidTransition applies the VOID transition with the acting officer (from
// verified claims, never client-supplied identity) and the refund transfer
// reference in the outbox event.
func (service *Service) voidTransition(ctx context.Context, ticket Ticket, refundID, principal, principalRole, correlationID string) (Ticket, error) {
	payload := map[string]any{
		"ticket_id":      ticket.TicketID,
		"principal_id":   principal,
		"principal_role": principalRole,
		"state":          string(StateVoid),
	}
	if refundID != "" {
		payload["ledger_transfer_id"] = refundID
	}
	return service.store.Transition(ctx, ticket.TicketID, ticket.Version, StateVoid, Event{
		EventID:       uuid.NewString(),
		Topic:         TopicTicketing,
		SubjectID:     ticket.TicketID,
		EventType:     EventTicketVoided,
		CorrelationID: correlationID,
		Payload:       payload,
	})
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
