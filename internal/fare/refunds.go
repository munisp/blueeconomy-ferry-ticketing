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
// ledger inside ONE advisory-locked transaction per refund: concurrent
// checkers serialize, the ledger leg executes at most once (deterministic
// transfer ID as backstop), and self-approval fails closed (SQL four-eyes).
// Approval of an already-APPROVED refund is the crash-recovery settle retry;
// approval of a SETTLED refund replays the stored record.
func (service *AccountService) ApproveAccountRefund(ctx context.Context, refundID, checker, correlationID string) (AccountRefund, error) {
	ctx, span := tracer().Start(ctx, "fare.account_refund.approve")
	defer span.End()
	if strings.TrimSpace(checker) == "" {
		return AccountRefund{}, errors.New("checker is required")
	}
	guard, refund, err := service.store.BeginAccountRefundGuard(ctx, refundID)
	if err != nil {
		return AccountRefund{}, err
	}
	defer guard.Rollback(ctx)
	switch refund.State {
	case RefundSettled:
		return refund, nil
	case RefundRejected:
		return AccountRefund{}, fmt.Errorf("refund %s is REJECTED: %w", refundID, ErrInvalidTransition)
	case RefundApproved:
		// Crash-recovery settle retry inside the guard.
	default: // REQUESTED
		refund, err = service.store.TransitionAccountRefundTx(ctx, guard, refund, RefundApproved, checker,
			service.event(EventAccountRefundApproved, refundID, correlationID, map[string]any{
				"refund_id":  refundID,
				"account_id": refund.AccountID,
				"maker":      refund.Maker,
				"checker":    checker,
				"state":      RefundApproved,
			}))
		if err != nil {
			return AccountRefund{}, err
		}
	}
	account, err := service.store.GetFareAccountTx(ctx, guard, refund.AccountID)
	if err != nil {
		return AccountRefund{}, err
	}
	transferID, err := service.accounts.RefundToAccount(ctx, refund.RefundID, account.LedgerAccountID, refund.AmountMinor)
	if err != nil {
		return AccountRefund{}, fmt.Errorf("settle account refund on ledger: %w", err)
	}
	if _, err := service.store.MarkAccountRefundSettledTx(ctx, guard, refund, transferID,
		service.event(EventAccountRefundSettled, refund.RefundID, correlationID, map[string]any{
			"refund_id":          refund.RefundID,
			"account_id":         refund.AccountID,
			"amount_ngn_minor":   refund.AmountMinor,
			"maker":              refund.Maker,
			"checker":            refund.Checker,
			"ledger_transfer_id": transferID,
			"state":              RefundSettled,
		})); err != nil {
		return AccountRefund{}, err
	}
	if err := guard.Commit(ctx); err != nil {
		return AccountRefund{}, fmt.Errorf("commit refund settle: %w", err)
	}
	return service.store.GetAccountRefund(ctx, refundID)
}

// RejectAccountRefund records the checker rejection (four-eyes in SQL,
// serialized through the same guard as approvals).
func (service *AccountService) RejectAccountRefund(ctx context.Context, refundID, checker, correlationID string) (AccountRefund, error) {
	if strings.TrimSpace(checker) == "" {
		return AccountRefund{}, errors.New("checker is required")
	}
	guard, refund, err := service.store.BeginAccountRefundGuard(ctx, refundID)
	if err != nil {
		return AccountRefund{}, err
	}
	defer guard.Rollback(ctx)
	if refund.State != RefundRequested {
		return AccountRefund{}, fmt.Errorf("refund %s is %s: %w", refundID, refund.State, ErrInvalidTransition)
	}
	rejected, err := service.store.TransitionAccountRefundTx(ctx, guard, refund, RefundRejected, checker,
		service.event(EventAccountRefundRejected, refundID, correlationID, map[string]any{
			"refund_id":  refundID,
			"account_id": refund.AccountID,
			"maker":      refund.Maker,
			"checker":    checker,
			"state":      RefundRejected,
		}))
	if err != nil {
		return AccountRefund{}, err
	}
	if err := guard.Commit(ctx); err != nil {
		return AccountRefund{}, fmt.Errorf("commit refund rejection: %w", err)
	}
	return rejected, nil
}
