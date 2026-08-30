//go:build integration

package fare

import (
	"context"
	"errors"
	"testing"
)

// PRA-134 integration: rail initiation binds the acceptance reference to
// the durable PENDING top-up; rail failure is an honest FAILED record;
// unconfigured channels fail closed.
func TestTopUpRailInitiationSemantics(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "rail-rider", ConcessionStandard, "", "agent:1", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	// Initiation: rail called with the durable reference, acceptance bound.
	topup, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 40000,
		IdempotencyKey: "rail-topup-1", CorrelationID: "corr", Principal: "passenger:rail-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if topup.State != TopUpPending || topup.ExternalRef != "test-rail:"+topup.Reference {
		t.Fatalf("top-up = %+v, want PENDING with bound acceptance ref", topup)
	}
	fixture.rails.mu.Lock()
	if len(fixture.rails.initiations) != 1 || fixture.rails.initiations[0].Reference != topup.Reference ||
		fixture.rails.initiations[0].AmountNGNMinor != 40000 {
		t.Fatalf("rail initiations = %+v", fixture.rails.initiations)
	}
	fixture.rails.mu.Unlock()
	// Nothing credited at initiation (credit is the verified webhook only).
	if len(fixture.accounts.credits) != 0 {
		t.Fatal("initiation must never credit")
	}
	// Initiate replay does NOT re-call the rail (durable idempotency).
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 40000,
		IdempotencyKey: "rail-topup-1", CorrelationID: "corr", Principal: "passenger:rail-rider",
	}); err != nil {
		t.Fatal(err)
	}
	fixture.rails.mu.Lock()
	if len(fixture.rails.initiations) != 1 {
		t.Fatalf("replay re-called the rail: %+v", fixture.rails.initiations)
	}
	fixture.rails.mu.Unlock()
	// Rail failure: honest FAILED record, nothing faked.
	fixture.rails.failNext = true
	failed, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpMojaloop, AmountNGNMinor: 10000,
		IdempotencyKey: "rail-topup-2", CorrelationID: "corr", Principal: "passenger:rail-rider",
	})
	if err == nil {
		t.Fatal("rail failure must surface")
	}
	stored, err := fixture.store.GetTopUpByIdempotency(ctx, "rail-topup-2")
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != TopUpFailed {
		t.Fatalf("failed top-up = %+v (returned %+v)", stored, failed)
	}
	// Unconfigured channel fails closed (fresh service without rails).
	bare, err := NewAccountService(fixture.store, fixture.accounts, testSalt, testWebhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 1000,
		IdempotencyKey: "rail-topup-3", CorrelationID: "corr", Principal: "passenger:rail-rider",
	}); !errors.Is(err, ErrRailNotConfigured) {
		t.Fatalf("unconfigured rail must fail closed, got %v", err)
	}
	// NQR stays payer-initiated: no rail adapter required.
	if _, err := bare.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNQR, AmountNGNMinor: 1000,
		IdempotencyKey: "rail-topup-4", CorrelationID: "corr", Principal: "passenger:rail-rider",
	}); err != nil {
		t.Fatalf("NQR must not require a rail adapter: %v", err)
	}
}
