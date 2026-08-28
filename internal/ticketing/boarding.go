package ticketing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

// Fraud-telemetry event types (topic ferries.ticketing.v1, envelope
// classification CONFIDENTIAL) consumed by the security-operations engine.
const (
	// EventTicketVerificationFailed audits a rejected artifact: invalid
	// signature, unknown kid, expired rotation grace, stale window code.
	EventTicketVerificationFailed = "ferry.ticket.verification_failed"
	// EventTicketDuplicatePresentation audits a second presentation of an
	// already-consumed boarding (first-scan-wins).
	EventTicketDuplicatePresentation = "ferry.ticket.duplicate_presentation"
)

var (
	// ErrTicketProofInvalid rejects an artifact that failed cryptographic
	// verification. The detail reason stays server-side (telemetry); callers
	// receive the sentinel only.
	ErrTicketProofInvalid = errors.New("ticket artifact verification failed")
	// ErrBoardingAlreadyConsumed rejects the second presentation of a
	// boarded ticket (HTTP 409 BOARDING_ALREADY_CONSUMED).
	ErrBoardingAlreadyConsumed = errors.New("boarding has already been consumed")
)

// BoardingStore is the persistence boundary for artifact minting and
// first-scan-wins boarding.
type BoardingStore interface {
	GetTicket(ctx context.Context, ticketID string) (Ticket, error)
	GetTrip(ctx context.Context, tripID string) (Trip, error)
	// ConsumeBoarding atomically marks one operator-scoped ISSUED ticket
	// boarded exactly once; consumed is false when the guard matched no row.
	ConsumeBoarding(ctx context.Context, operatorID, ticketID, boardedBy, artifactKid string) (consumed bool, err error)
	// AppendEvent writes one standalone fraud-telemetry outbox event.
	AppendEvent(ctx context.Context, event Event) error
}

// BoardingService mints signed ticket artifacts, verifies them and consumes
// boardings first-scan-wins. It fails closed without a signing key set and a
// window secret: no key material is ever fabricated or defaulted.
type BoardingService struct {
	store    BoardingStore
	keys     *ticketproof.KeySet
	verifier *ticketproof.Verifier
	now      func() time.Time
}

// Artifact is the minted, QR-encodable signed ticket payload.
type Artifact struct {
	Token         string    `json:"artifact"`
	KeyID         string    `json:"kid"`
	TicketID      string    `json:"ticketId"`
	TripID        string    `json:"tripId"`
	SeatNumber    int       `json:"seatNumber"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	RotationEpoch uint32    `json:"rotationEpoch"`
}

// NewBoardingService fails closed on any missing dependency.
func NewBoardingService(store BoardingStore, keys *ticketproof.KeySet, windowSecret string) (*BoardingService, error) {
	if store == nil {
		return nil, errors.New("boarding store is required")
	}
	if keys == nil {
		return nil, errors.New("ticket signing key set is required (fail-closed)")
	}
	if len(windowSecret) < 16 {
		return nil, errors.New("ticket window secret of at least 16 characters is required (fail-closed)")
	}
	verifier, err := keys.Verifier(windowSecret)
	if err != nil {
		return nil, err
	}
	return &BoardingService{
		store: store, keys: keys, verifier: verifier,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// MintArtifact produces the signed artifact for an ISSUED ticket. The
// artifact is minted on demand (nothing per-ticket is stored): issued_at is
// the mint instant, expires_at is the trip's scheduled departure so artifacts
// die with the voyage, and the rotating window code is current at mint time.
func (service *BoardingService) MintArtifact(ctx context.Context, ticketID string) (Artifact, error) {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil {
		return Artifact{}, err
	}
	if ticket.State != StateIssued {
		return Artifact{}, fmt.Errorf("%w: %s tickets cannot mint a boarding artifact", ErrInvalidTransition, ticket.State)
	}
	trip, err := service.store.GetTrip(ctx, ticket.TripID)
	if err != nil {
		return Artifact{}, fmt.Errorf("load trip for artifact: %w", err)
	}
	now := service.now()
	payload := ticketproof.Payload{
		TicketID:     ticket.TicketID,
		TripID:       ticket.TripID,
		Seat:         ticket.SeatNumberValue(),
		IssuedAt:     now,
		ExpiresAt:    trip.ScheduledDeparture.UTC(),
		HolderDigest: ticket.PassengerDigest,
	}
	token, err := service.keys.Sign(payload, service.verifierWindowSecret(), now)
	if err != nil {
		return Artifact{}, fmt.Errorf("sign ticket artifact: %w", err)
	}
	return Artifact{
		Token:         token,
		KeyID:         service.keys.CurrentKeyID(),
		TicketID:      ticket.TicketID,
		TripID:        ticket.TripID,
		SeatNumber:    payload.Seat,
		IssuedAt:      now,
		ExpiresAt:     payload.ExpiresAt,
		RotationEpoch: service.keys.RotationEpoch(),
	}, nil
}

// VerificationKeys returns the distributable public key set for offline
// verifiers (served by GET /v1/tickets/verification-keys). The previous key
// is reported only while it is still inside its rotation grace window; once
// the deadline passes it is no longer trusted and is withheld, so a fresh
// key-set fetch always reflects exactly what this service would accept.
func (service *BoardingService) VerificationKeys() (current ticketproof.VerificationKey, previous *ticketproof.VerificationKey) {
	current, previous = service.keys.VerificationKeys()
	if previous != nil && !service.now().Before(previous.GraceUntil) {
		previous = nil
	}
	return current, previous
}

// VerifyArtifact is the stateless authenticity check (signature, key id,
// rotation grace, artifact expiry, rotating window code). Verification needs
// no database; a failure emits the TicketVerificationFailed fraud event.
func (service *BoardingService) VerifyArtifact(ctx context.Context, token, principal, correlationID string) (ticketproof.Payload, error) {
	payload, err := service.verifier.Verify(token, service.now())
	if err == nil {
		return payload, nil
	}
	service.emitFraudEvent(ctx, EventTicketVerificationFailed, payload.TicketID, "", payload.KeyID, principal, correlationID, map[string]any{
		"reason": ticketproof.FailureReason(err),
	})
	return ticketproof.Payload{}, fmt.Errorf("%w: %s", ErrTicketProofInvalid, ticketproof.FailureReason(err))
}

// Embark consumes one boarding first-scan-wins. With an artifact the
// presentation is verified cryptographically before the atomic consume; the
// artifact's ticket_id must match the path ticket. The legacy path (empty
// artifact) consumes by raw ticket id only and is retained for backward
// compatibility. A second presentation — concurrent or later — returns
// ErrBoardingAlreadyConsumed and emits TicketDuplicatePresentation.
func (service *BoardingService) Embark(ctx context.Context, operatorID, ticketID, artifact, principal, correlationID string) (Ticket, error) {
	if operatorID == "" || ticketID == "" || principal == "" {
		return Ticket{}, errors.New("operator id, ticket id and boarding principal are required")
	}
	artifactKid := ""
	if artifact != "" {
		payload, err := service.verifier.Verify(artifact, service.now())
		if err != nil {
			service.emitFraudEvent(ctx, EventTicketVerificationFailed, ticketID, "", payload.KeyID, principal, correlationID, map[string]any{
				"reason": ticketproof.FailureReason(err),
			})
			return Ticket{}, fmt.Errorf("%w: %s", ErrTicketProofInvalid, ticketproof.FailureReason(err))
		}
		if payload.TicketID != ticketID {
			service.emitFraudEvent(ctx, EventTicketVerificationFailed, ticketID, payload.TripID, payload.KeyID, principal, correlationID, map[string]any{
				"reason": "ticket_id_mismatch",
			})
			return Ticket{}, fmt.Errorf("%w: ticket_id_mismatch", ErrTicketProofInvalid)
		}
		artifactKid = payload.KeyID
	}
	consumed, err := service.store.ConsumeBoarding(ctx, operatorID, ticketID, principal, artifactKid)
	if err != nil {
		return Ticket{}, err
	}
	if !consumed {
		return Ticket{}, service.boardingRejected(ctx, operatorID, ticketID, artifactKid, principal, correlationID)
	}
	return service.store.GetTicket(ctx, ticketID)
}

// boardingRejected distinguishes an unknown/unboardable ticket (no existence
// leak: ErrNotFound) from a duplicate presentation (fraud signal + 409).
func (service *BoardingService) boardingRejected(ctx context.Context, operatorID, ticketID, artifactKid, principal, correlationID string) error {
	ticket, err := service.store.GetTicket(ctx, ticketID)
	if err != nil || ticket.OperatorID != operatorID || ticket.State != StateIssued {
		return ErrNotFound
	}
	if ticket.BoardedAt != nil {
		service.emitFraudEvent(ctx, EventTicketDuplicatePresentation, ticketID, ticket.TripID, artifactKid, principal, correlationID, map[string]any{
			"trip_id":            ticket.TripID,
			"first_boarded_at":   ticket.BoardedAt.UTC().Format(time.RFC3339),
			"first_boarded_by":   ticket.BoardedBy,
			"first_artifact_kid": ticket.ArtifactKid,
		})
		return ErrBoardingAlreadyConsumed
	}
	return ErrNotFound
}

// emitFraudEvent writes one CONFIDENTIAL fraud-telemetry event to the
// transactional outbox. Emission failure never masks the security decision
// (boarding is already fail-closed); the payload carries no PII.
func (service *BoardingService) emitFraudEvent(ctx context.Context, eventType, ticketID, tripID, kid, principal, correlationID string, extra map[string]any) {
	subject := ticketID
	if subject == "" {
		subject = "unknown"
	}
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	payload := map[string]any{
		"ticket_id":    ticketID,
		"principal_id": principal,
		"artifact_kid": kid,
	}
	if tripID != "" {
		payload["trip_id"] = tripID
	}
	for key, value := range extra {
		payload[key] = value
	}
	_ = service.store.AppendEvent(ctx, Event{
		EventID:       uuid.NewString(),
		Topic:         TopicTicketing,
		SubjectID:     subject,
		EventType:     eventType,
		CorrelationID: correlationID,
		Payload:       payload,
	})
}

// verifierWindowSecret exposes the configured window secret for minting.
func (service *BoardingService) verifierWindowSecret() string {
	return service.verifier.WindowSecret()
}
