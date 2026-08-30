//go:build integration

package fare

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// PRA-136: refunds TO fare accounts — saga, four-eyes, exactly-once, replay.
func TestAccountRefundSagaExactlyOnceAndReplay(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "refund-rider", ConcessionStandard, "", "agent:1", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpAgentCash, AmountNGNMinor: 50000,
		AgentID: "agent-1", IdempotencyKey: "ref-topup", CorrelationID: "corr", Principal: "agent:1",
	}); err != nil {
		t.Fatal(err)
	}
	request := AccountRefundRequest{
		AccountID: account.AccountID, AmountMinor: 20000, Reason: "service disruption goodwill",
		IdempotencyKey: "refund-1", CorrelationID: "corr-refund", Principal: "officer:maker",
	}
	refund, err := fixture.accountSvc.RequestAccountRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if refund.State != RefundRequested || refund.Maker != "officer:maker" {
		t.Fatalf("refund = %+v", refund)
	}
	// Replay returns the original; a different amount on the same key conflicts.
	replayed, err := fixture.accountSvc.RequestAccountRefund(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.RefundID != refund.RefundID {
		t.Fatal("replay must return the original refund")
	}
	conflicting := request
	conflicting.AmountMinor = 20001
	if _, err := fixture.accountSvc.RequestAccountRefund(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay must fail, got %v", err)
	}
	// Self-approval fails closed at SQL level; the row stays REQUESTED.
	if _, err := fixture.accountSvc.ApproveAccountRefund(ctx, refund.RefundID, "officer:maker", "corr"); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("self-approval must fail, got %v", err)
	}
	stored, err := fixture.store.GetAccountRefund(ctx, refund.RefundID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != RefundRequested || stored.Checker != "" {
		t.Fatalf("after refused approval = %+v", stored)
	}
	// Concurrent approvals by distinct checkers: exactly one settles, the
	// ledger sees exactly one refund transfer.
	const approvers = 6
	var wait sync.WaitGroup
	results := make(chan error, approvers)
	for i := 0; i < approvers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			checker := "officer:checker"
			if index%2 == 1 {
				checker = "officer:checker-b"
			}
			_, err := fixture.accountSvc.ApproveAccountRefund(ctx, refund.RefundID, checker, "corr-race")
			results <- err
		}(i)
	}
	wait.Wait()
	close(results)
	for err := range results {
		// Losers get an honest transition error, never a double settle.
		if err != nil && !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("unexpected approval error: %v", err)
		}
	}
	settled, err := fixture.store.GetAccountRefund(ctx, refund.RefundID)
	if err != nil {
		t.Fatal(err)
	}
	if settled.State != RefundSettled || settled.LedgerTransferID == "" || settled.SettledAt == nil {
		t.Fatalf("settled refund = %+v", settled)
	}
	if len(fixture.accounts.refunds) != 1 || fixture.accounts.refunds[0].amount != 20000 {
		t.Fatalf("ledger refunds = %+v, want exactly one 20000", fixture.accounts.refunds)
	}
	// Approval replay after settlement returns the stored record, no money.
	again, err := fixture.accountSvc.ApproveAccountRefund(ctx, refund.RefundID, "officer:checker", "corr-replay")
	if err != nil {
		t.Fatal(err)
	}
	if again.State != RefundSettled || len(fixture.accounts.refunds) != 1 {
		t.Fatalf("settled replay double-moved value: %+v", again)
	}
	// Reconciliation view: refund flows into the balance with zero drift.
	view, err := fixture.accountSvc.GetAccountView(ctx, account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if view.RefundedMinor != 20000 || view.FlowBalanceMinor != 70000 || view.CacheDriftMinor != 0 {
		t.Fatalf("view = %+v", view)
	}
	// Rejection path: a distinct checker rejects; settlement never happens.
	second, err := fixture.accountSvc.RequestAccountRefund(ctx, AccountRefundRequest{
		AccountID: account.AccountID, AmountMinor: 5000, Reason: "duplicate charge",
		IdempotencyKey: "refund-2", CorrelationID: "corr", Principal: "officer:maker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.RejectAccountRefund(ctx, second.RefundID, "officer:maker", "corr"); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("self-rejection must fail, got %v", err)
	}
	rejected, err := fixture.accountSvc.RejectAccountRefund(ctx, second.RefundID, "officer:checker", "corr")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.State != RefundRejected {
		t.Fatalf("rejected = %+v", rejected)
	}
	if _, err := fixture.accountSvc.ApproveAccountRefund(ctx, second.RefundID, "officer:checker", "corr"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approving a rejected refund must fail, got %v", err)
	}
	if len(fixture.accounts.refunds) != 1 {
		t.Fatal("rejected refund must never reach the ledger")
	}
}
