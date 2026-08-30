package fare

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// refunds.go — PRA-136: refunds TO BlueFare fare accounts. The saga:
//
//	maker REQUESTED --(distinct checker)--> APPROVED --(ledger, exactly-once)--> SETTLED
//	                                     \-> REJECTED
//
// Money moves via ledger.RefundToAccount (operator revenue -> fare account)
// with the deterministic transfer ID derived from refund_id, so a crash
// between ledger and PG or a retried approval never double-moves value.
// Four-eyes is enforced in SQL (transitionAccountRefund), mirroring the
// repo's void dual-control doctrine.

// AccountRefundRequest carries one refund-to-account request.
type AccountRefundRequest struct {
	AccountID      string
	AmountMinor    int64
	Reason         string
	IdempotencyKey string
	CorrelationID  string
	Principal      string
}

// RequestAccountRefund registers one refund request (maker). Replay of the
// same idempotency key returns the original refund; the same key against a
// different amount or account conflicts.
func (service *AccountService) RequestAccountRefund(ctx context.Context, request AccountRefundRequest) (AccountRefund, error) {
	ctx, span := tracer().Start(ctx, "fare.account_refund.request")
	defer span.End()
	if strings.TrimSpace(request.AccountID) == "" || request.AmountMinor <= 0 {
		return AccountRefund{}, errors.New("account id and positive amount are required")
	}
	if strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		return AccountRefund{}, errors.New("a refund reason is required")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 128 {
		return AccountRefund{}, errors.New("idempotency key is required")
	}
	if strings.TrimSpace(request.Principal) == "" {
		return AccountRefund{}, errors.New("principal is required")
	}
	account, err := service.store.GetFareAccount(ctx, request.AccountID)
	if err != nil {
		return AccountRefund{}, err
	}
	if account.Status != "ACTIVE" {
		return AccountRefund{}, ErrAccountNotActive
	}
	if existing, err := service.store.GetAccountRefundByIdempotency(ctx, request.IdempotencyKey); err == nil {
		if existing.AccountID != request.AccountID || existing.AmountMinor != request.AmountMinor {
			return AccountRefund{}, ErrIdempotencyConflict
		}
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return AccountRefund{}, fmt.Errorf("resolve idempotency key: %w", err)
	}
	refund := AccountRefund{
		RefundID:       uuid.NewString(),
		AccountID:      request.AccountID,
		AmountMinor:    request.AmountMinor,
		Reason:         request.Reason,
		IdempotencyKey: request.IdempotencyKey,
		State:          RefundRequested,
		Maker:          request.Principal,
		Version:        1,
		CorrelationID:  request.CorrelationID,
	}
	if err := service.store.InsertAccountRefund(ctx, refund, service.event(EventAccountRefundRequested, refund.RefundID, request.CorrelationID, map[string]any{
		"refund_id":        refund.RefundID,
		"account_id":       refund.AccountID,
		"amount_ngn_minor": refund.AmountMinor,
		"reason":           refund.Reason,
		"maker":            refund.Maker,
		"state":            RefundRequested,
	})); err != nil {
		return AccountRefund{}, err
	}
	return service.store.GetAccountRefund(ctx, refund.RefundID)
}

// ApproveAccountRefund applies the checker decision and settles through the
// ledger in one saga step. Self-approval fails closed (SQL four-eyes).
// Approval of an already-approved refund re-attempts settlement (the ledger
// transfer ID is deterministic — the re-attempt is a no-op cluster-side);
// approval of a SETTLED refund replays the stored record.
func (service *AccountService) ApproveAccountRefund(ctx context.Context, refundID, checker, correlationID string) (AccountRefund, error) {
	ctx, span := tracer().Start(ctx, "fare.account_refund.approve")
	defer span.End()
	if strings.TrimSpace(checker) == "" {
		return AccountRefund{}, errors.New("checker is required")
	}
	stored, err := service.store.GetAccountRefund(ctx, refundID)
	if err != nil {
		return AccountRefund{}, err
	}
	switch stored.State {
	case RefundSettled:
		return stored, nil
	case RefundRejected:
		return AccountRefund{}, fmt.Errorf("refund %s is REJECTED: %w", refundID, ErrInvalidTransition)
	case RefundApproved:
		// Settle retry (crash recovery or a replayed approval).
		return service.settleAccountRefund(ctx, stored, correlationID)
	}
	refund, err := service.store.transitionAccountRefund(ctx, refundID, RefundRequested, RefundApproved, checker,
		service.event(EventAccountRefundApproved, refundID, correlationID, map[string]any{
			"refund_id":  refundID,
			"account_id": stored.AccountID,
			"maker":      stored.Maker,
			"checker":    checker,
			"state":      RefundApproved,
		}))
	if err != nil {
		return AccountRefund{}, err
	}
	return service.settleAccountRefund(ctx, refund, correlationID)
}

// settleAccountRefund moves value exactly once against the ledger, then
// records settlement. The deterministic transfer ID (refund_id) makes the
// ledger leg idempotent; the version-gated PG update makes the record leg
// replay-safe.
func (service *AccountService) settleAccountRefund(ctx context.Context, refund AccountRefund, correlationID string) (AccountRefund, error) {
	account, err := service.store.GetFareAccount(ctx, refund.AccountID)
	if err != nil {
		return AccountRefund{}, err
	}
	transferID, err := service.accounts.RefundToAccount(ctx, refund.RefundID, account.LedgerAccountID, refund.AmountMinor)
	if err != nil {
		return AccountRefund{}, fmt.Errorf("settle account refund on ledger: %w", err)
	}
	settled, err := service.store.MarkAccountRefundSettled(ctx, refund, transferID,
		service.event(EventAccountRefundSettled, refund.RefundID, correlationID, map[string]any{
			"refund_id":          refund.RefundID,
			"account_id":         refund.AccountID,
			"amount_ngn_minor":   refund.AmountMinor,
			"maker":              refund.Maker,
			"checker":            refund.Checker,
			"ledger_transfer_id": transferID,
			"state":              RefundSettled,
		}))
	if err != nil {
		return AccountRefund{}, err
	}
	if !settled {
		// A concurrent twin settled first; its record is authoritative.
		return service.store.GetAccountRefund(ctx, refund.RefundID)
	}
	return service.store.GetAccountRefund(ctx, refund.RefundID)
}

// RejectAccountRefund records the checker rejection (four-eyes in SQL).
func (service *AccountService) RejectAccountRefund(ctx context.Context, refundID, checker, correlationID string) (AccountRefund, error) {
	if strings.TrimSpace(checker) == "" {
		return AccountRefund{}, errors.New("checker is required")
	}
	stored, err := service.store.GetAccountRefund(ctx, refundID)
	if err != nil {
		return AccountRefund{}, err
	}
	if stored.State != RefundRequested {
		return AccountRefund{}, fmt.Errorf("refund %s is %s: %w", refundID, stored.State, ErrInvalidTransition)
	}
	return service.store.transitionAccountRefund(ctx, refundID, RefundRequested, RefundRejected, checker,
		service.event(EventAccountRefundRejected, refundID, correlationID, map[string]any{
			"refund_id":  refundID,
			"account_id": stored.AccountID,
			"maker":      stored.Maker,
			"checker":    checker,
			"state":      RefundRejected,
		}))
}
