package fare

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// PassPurchaseRequest carries one pass purchase. PassengerRef is the opaque,
// tokenized owner reference; it is digested before persistence (no PII).
type PassPurchaseRequest struct {
	ProductID      string
	PassengerRef   string
	Channel        string
	AgentID        string
	AccountID      string // required for ChannelAccount
	IdempotencyKey string
	CorrelationID  string
	Principal      string
	PrincipalRole  string
}

// Validate fails closed on any malformed request.
func (request PassPurchaseRequest) Validate() error {
	if strings.TrimSpace(request.ProductID) == "" {
		return errors.New("product_id is required")
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
			return errors.New("account_id is required for account purchases")
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

// PassService runs the pass purchase saga on the SAME discipline as the
// ticket booking saga: two-phase ledger reserve -> durable reservation with
// idempotency key -> post -> issue, outbox events in the same transaction,
// deterministic transfer IDs deduplicating cluster-side, replay resuming the
// interrupted step instead of double-charging.
type PassService struct {
	store    *PostgresStore
	tickets  ticketing.Ledger
	accounts AccountLedger
	salt     string
	now      func() time.Time
}

// NewPassService fails closed on any missing dependency.
func NewPassService(store *PostgresStore, tickets ticketing.Ledger, accounts AccountLedger, manifestSalt string) (*PassService, error) {
	if store == nil {
		return nil, errors.New("fare store is required")
	}
	if tickets == nil {
		return nil, errors.New("ticket ledger is required (fail-closed)")
	}
	if accounts == nil {
		return nil, errors.New("account ledger is required (fail-closed)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	return &PassService{store: store, tickets: tickets, accounts: accounts, salt: manifestSalt,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// CreatePassProduct registers one product (operator or ministry scope).
func (service *PassService) CreatePassProduct(ctx context.Context, product PassProduct) error {
	if product.ProductID == "" {
		return errors.New("product id is required")
	}
	if _, err := PassDuration(product.Kind); err != nil {
		return err
	}
	switch product.ScopeType {
	case ScopeTypeNetwork:
		if product.ScopeRef != "" {
			return errors.New("NETWORK products carry no scope reference")
		}
	case ScopeTypeRoute, ScopeTypeZone:
		if strings.TrimSpace(product.ScopeRef) == "" {
			return errors.New("ROUTE and ZONE products require a scope reference")
		}
	default:
		return fmt.Errorf("scope type %q is not supported", product.ScopeType)
	}
	if product.PriceNGNMinor <= 0 {
		return errors.New("product price must be positive")
	}
	return service.store.CreatePassProduct(ctx, product)
}

// Purchase runs the pass purchase saga. Replay of the same idempotency key
// returns the original pass (never a second charge).
func (service *PassService) Purchase(ctx context.Context, request PassPurchaseRequest) (Pass, error) {
	// BlueFare pass saga span: RESERVED → PAID → ISSUED across the ledger
	// reserve/post and the store transitions (child spans carry detail).
	ctx, span := tracer().Start(ctx, "ferry.bluefare.pass_saga",
		trace.WithAttributes(
			attribute.String("ferry.pass_product_id", request.ProductID),
			attribute.String("ferry.channel", request.Channel),
		))
	defer span.End()
	if err := request.Validate(); err != nil {
		return Pass{}, err
	}
	product, err := service.store.GetPassProduct(ctx, request.ProductID)
	if err != nil {
		return Pass{}, fmt.Errorf("load pass product: %w", err)
	}
	if !product.Active {
		return Pass{}, fmt.Errorf("pass product %s is not active", product.ProductID)
	}
	digest, err := ticketing.PassengerDigest(service.salt, request.PassengerRef)
	if err != nil {
		return Pass{}, err
	}
	// Idempotent replay resolves BEFORE any ledger movement.
	if existing, err := service.store.GetPassPurchaseByIdempotency(ctx, request.IdempotencyKey); err == nil {
		if existing.PurchaserPrincipal != request.Principal {
			return Pass{}, ErrIdempotencyConflict
		}
		return service.complete(ctx, existing, product)
	} else if !errors.Is(err, ErrNotFound) {
		return Pass{}, fmt.Errorf("resolve idempotency key: %w", err)
	}
	var account FareAccount
	if request.Channel == ChannelAccount {
		account, err = service.store.GetFareAccount(ctx, request.AccountID)
		if err != nil {
			return Pass{}, fmt.Errorf("load fare account: %w", err)
		}
		if account.Status != "ACTIVE" {
			return Pass{}, ErrAccountNotActive
		}
	}
	purchase := PassPurchase{
		PurchaseID:         uuid.NewString(),
		ProductID:          product.ProductID,
		OwnerDigest:        digest,
		PriceNGNMinor:      product.PriceNGNMinor,
		Channel:            request.Channel,
		AgentID:            request.AgentID,
		AccountID:          request.AccountID,
		State:              PurchaseReserved,
		Version:            1,
		PurchaserPrincipal: request.Principal,
		CorrelationID:      request.CorrelationID,
		IdempotencyKey:     request.IdempotencyKey,
	}
	reserveID, err := service.reserve(ctx, purchase, account)
	if err != nil {
		return Pass{}, fmt.Errorf("reserve pass price on ledger: %w", err)
	}
	purchase.LedgerReserveID = reserveID
	if err := service.store.InsertPassPurchase(ctx, purchase, service.event(EventPassReserved, purchase.PurchaseID, purchase.CorrelationID, map[string]any{
		"purchase_id": purchase.PurchaseID,
		"product_id":  product.ProductID,
		"channel":     purchase.Channel,
		"principal_id": purchase.PurchaserPrincipal,
		"state":       PurchaseReserved,
	})); err != nil {
		// Compensate the ledger reserve; the purchase never happened. A
		// duplicate idempotency key means a concurrent twin won: resume it.
		if voidErr := service.tickets.Void(ctx, reserveID); voidErr != nil {
			return Pass{}, fmt.Errorf("record pass purchase: %w; ledger void compensation also failed: %v", err, voidErr)
		}
		if existing, lookupErr := service.store.GetPassPurchaseByIdempotency(ctx, request.IdempotencyKey); lookupErr == nil {
			if existing.PurchaserPrincipal != request.Principal {
				return Pass{}, ErrIdempotencyConflict
			}
			return service.complete(ctx, existing, product)
		}
		return Pass{}, fmt.Errorf("record pass purchase: %w", err)
	}
	return service.complete(ctx, purchase, product)
}

// reserve creates the two-phase hold: account debit for ACCOUNT purchases,
// the ticket-channel reserve otherwise.
func (service *PassService) reserve(ctx context.Context, purchase PassPurchase, account FareAccount) (string, error) {
	if purchase.Channel == ChannelAccount {
		return service.accounts.ReserveFromAccount(ctx, purchase.PurchaseID, account.LedgerAccountID, purchase.PriceNGNMinor)
	}
	return service.tickets.Reserve(ctx, purchase.PurchaseID, ticketing.Channel(purchase.Channel), purchase.PriceNGNMinor)
}

// complete drives a RESERVED or PAID purchase through settlement and pass
// issuance — the shared tail for the fresh path and idempotent replay.
func (service *PassService) complete(ctx context.Context, purchase PassPurchase, product PassProduct) (Pass, error) {
	switch purchase.State {
	case PurchaseIssued:
		return service.store.GetPass(ctx, purchase.PassID)
	case PurchaseReserved:
		postID, err := service.tickets.Post(ctx, purchase.LedgerReserveID)
		if err != nil {
			return Pass{}, fmt.Errorf("settle pass price on ledger: %w", err)
		}
		purchase, err = service.store.MarkPassPurchasePaid(ctx, purchase.PurchaseID, purchase.Version, postID, service.event(EventPassPaid, purchase.PurchaseID, purchase.CorrelationID, map[string]any{
			"purchase_id":        purchase.PurchaseID,
			"product_id":         product.ProductID,
			"ledger_transfer_id": postID,
			"principal_id":       purchase.PurchaserPrincipal,
			"state":              PurchasePaid,
		}))
		if err != nil {
			return Pass{}, err
		}
		fallthrough
	case PurchasePaid:
		duration, err := PassDuration(product.Kind)
		if err != nil {
			return Pass{}, err
		}
		now := service.now()
		pass := Pass{
			PassID:      uuid.NewString(),
			ProductID:   product.ProductID,
			OwnerDigest: purchase.OwnerDigest,
			ValidFrom:   now,
			ValidTo:     now.Add(duration),
			Status:      PassStatusActive,
			PurchaseID:  purchase.PurchaseID,
		}
		issued, err := service.store.IssuePass(ctx, purchase.PurchaseID, purchase.Version, pass, service.event(EventPassIssued, pass.PassID, purchase.CorrelationID, map[string]any{
			"pass_id":      pass.PassID,
			"purchase_id":  purchase.PurchaseID,
			"product_id":   product.ProductID,
			"kind":         product.Kind,
			"scope_type":   product.ScopeType,
			"scope_ref":    product.ScopeRef,
			"valid_from":   pass.ValidFrom.Format(time.RFC3339),
			"valid_to":     pass.ValidTo.Format(time.RFC3339),
			"principal_id": purchase.PurchaserPrincipal,
			"state":        PurchaseIssued,
		}))
		if err != nil {
			return Pass{}, fmt.Errorf("issue pass: %w", err)
		}
		if purchase.Channel == ChannelAccount {
			// Reflect the settled debit in the balance read-model (the ledger
			// remains authoritative).
			if err := service.adjustBalanceCache(ctx, purchase.AccountID, -purchase.PriceNGNMinor); err != nil {
				return Pass{}, fmt.Errorf("update balance cache: %w", err)
			}
		}
		return issued, nil
	default:
		return Pass{}, fmt.Errorf("%w: pass purchase in state %s", ErrInvalidTransition, purchase.State)
	}
}

// adjustBalanceCache moves the read-model in one small transaction.
func (service *PassService) adjustBalanceCache(ctx context.Context, accountID string, delta int64) error {
	tx, err := service.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := service.store.AdjustCachedBalance(ctx, tx, accountID, delta); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Suspend halts a pass (lost device, investigation); reversible.
func (service *PassService) Suspend(ctx context.Context, passID, principal, correlationID string) (Pass, error) {
	pass, err := service.store.GetPass(ctx, passID)
	if err != nil {
		return Pass{}, err
	}
	return service.store.TransitionPass(ctx, passID, pass.Version, []string{PassStatusActive}, PassStatusSuspended, "",
		service.event(EventPassSuspended, passID, correlationID, map[string]any{
			"pass_id": passID, "principal_id": principal, "state": PassStatusSuspended,
		}))
}

// Unsuspend restores a suspended pass.
func (service *PassService) Unsuspend(ctx context.Context, passID, principal, correlationID string) (Pass, error) {
	pass, err := service.store.GetPass(ctx, passID)
	if err != nil {
		return Pass{}, err
	}
	return service.store.TransitionPass(ctx, passID, pass.Version, []string{PassStatusSuspended}, PassStatusActive, "",
		service.event(EventPassSuspended, passID, correlationID, map[string]any{
			"pass_id": passID, "principal_id": principal, "state": PassStatusActive,
		}))
}

// Revoke permanently kills a pass and publishes it to the device blocklist.
// Revocation is a safety/fraud control, not a money movement; it is audited
// like every other transition.
func (service *PassService) Revoke(ctx context.Context, passID, principal, reason, correlationID string) (Pass, error) {
	pass, err := service.store.GetPass(ctx, passID)
	if err != nil {
		return Pass{}, err
	}
	return service.store.TransitionPass(ctx, passID, pass.Version, []string{PassStatusActive, PassStatusSuspended}, PassStatusRevoked, reason,
		service.event(EventPassRevoked, passID, correlationID, map[string]any{
			"pass_id": passID, "principal_id": principal, "reason": reason, "state": PassStatusRevoked,
		}))
}

// SweepExpiredPasses expires ACTIVE passes whose validity elapsed (nightly
// worker sweep; every transition carries its outbox event).
func (service *PassService) SweepExpiredPasses(ctx context.Context, limit int) (int, error) {
	return SweepExpiredPasses(ctx, service.store, service.now(), limit)
}

// SweepExpiredPasses is the store-level expiry sweep used by the worker:
// ACTIVE passes past valid_to transition to EXPIRED with audit events. Cap
// accumulator rollover is intentionally NOT swept here — it is lazy (period
// rows are keyed by the derived period start on read/write).
func SweepExpiredPasses(ctx context.Context, store *PostgresStore, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, errors.New("sweep batch limit must be positive")
	}
	expired, err := store.ListActivePassesExpiringBefore(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	swept := 0
	for _, pass := range expired {
		if _, err := store.TransitionPass(ctx, pass.PassID, pass.Version, []string{PassStatusActive}, PassStatusExpired, "",
			ticketing.Event{
				EventID:       uuid.NewString(),
				Topic:         TopicFare,
				SubjectID:     pass.PassID,
				EventType:     EventPassExpired,
				CorrelationID: uuid.NewString(),
				Payload:       map[string]any{"pass_id": pass.PassID, "state": PassStatusExpired},
			}); err != nil {
			return swept, fmt.Errorf("expire pass %s: %w", pass.PassID, err)
		}
		swept++
	}
	return swept, nil
}

func (service *PassService) event(eventType, subjectID, correlationID string, payload map[string]any) ticketing.Event {
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
