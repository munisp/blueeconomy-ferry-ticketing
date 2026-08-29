//go:build integration

package fare

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/passproof"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

// --- validation + blocklist -------------------------------------------------

type validationFixture struct {
	fareFixture
	signer     *passproof.Signer
	validation *ValidationService
}

func newValidationFixture(t *testing.T) validationFixture {
	t.Helper()
	fixture := newFareFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := passproof.NewSigner(privateKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := NewValidationService(fixture.store, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.ProvisionKeyDirectory(context.Background()); err != nil {
		t.Fatal(err)
	}
	return validationFixture{fixture, signer, validation}
}

func (fixture validationFixture) buyPass(t *testing.T, productID, passengerRef, key string) Pass {
	t.Helper()
	pass, err := fixture.passes.Purchase(context.Background(), PassPurchaseRequest{
		ProductID: productID, PassengerRef: passengerRef, Channel: ChannelDirect,
		IdempotencyKey: key, CorrelationID: "corr-val", Principal: "passenger:" + passengerRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pass
}

func TestOfflineValidationAdmitDenyMatrix(t *testing.T) {
	fixture := newValidationFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.passes.CreatePassProduct(ctx, PassProduct{
		ProductID: "prod-val-week", Kind: PassKindWeek, ScopeType: ScopeTypeNetwork, PriceNGNMinor: 100000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.passes.CreatePassProduct(ctx, PassProduct{
		ProductID: "prod-val-route", Kind: PassKindDay, ScopeType: ScopeTypeRoute, ScopeRef: "route-a", PriceNGNMinor: 20000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}

	pass := fixture.buyPass(t, "prod-val-week", "val-1", "val-purchase-1")
	artifact, err := fixture.validation.MintArtifact(ctx, pass.PassID)
	if err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, artifact, ""); !decision.Admit {
		t.Fatalf("active pass must ADMIT, got %+v", decision)
	}

	// Revoked pass denies with the blocklist reason, no PII.
	if _, err := fixture.passes.Revoke(ctx, pass.PassID, "officer:1", "reported stolen", "corr-revoke"); err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, artifact, ""); decision.Admit || decision.Reason != "revoked" {
		t.Fatalf("revoked pass must DENY revoked, got %+v", decision)
	}

	// Suspended pass denies; unsuspension admits again.
	suspended := fixture.buyPass(t, "prod-val-week", "val-2", "val-purchase-2")
	suspendedArtifact, _ := fixture.validation.MintArtifact(ctx, suspended.PassID)
	if _, err := fixture.passes.Suspend(ctx, suspended.PassID, "officer:1", "corr-suspend"); err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, suspendedArtifact, ""); decision.Admit || decision.Reason != "suspended" {
		t.Fatalf("suspended pass must DENY suspended, got %+v", decision)
	}

	// Expired artifact denies (validity window in the signed payload).
	if _, err := fixture.pool.Exec(ctx,
		`UPDATE passes SET valid_from = $2, valid_to = $3 WHERE pass_id = $1`,
		pass.PassID, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	stale, err := fixture.signer.Sign(passproof.Payload{
		PassID: pass.PassID, ProductID: "prod-val-week", ScopeType: passproof.ScopeNetwork,
		ValidFrom: time.Now().Add(-48 * time.Hour), ValidTo: time.Now().Add(-time.Hour),
		HolderDigest: pass.OwnerDigest,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, stale, ""); decision.Admit || decision.Reason != "expired" {
		t.Fatalf("expired pass must DENY expired, got %+v", decision)
	}

	// Not-yet-valid artifact denies not_valid_yet.
	future, err := fixture.signer.Sign(passproof.Payload{
		PassID: pass.PassID, ProductID: "prod-val-week", ScopeType: passproof.ScopeNetwork,
		ValidFrom: time.Now().Add(time.Hour), ValidTo: time.Now().Add(25 * time.Hour),
		HolderDigest: pass.OwnerDigest,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, future, ""); decision.Admit || decision.Reason != "not_valid_yet" {
		t.Fatalf("future pass must DENY not_valid_yet, got %+v", decision)
	}

	// Wrong epoch: a device holding only epoch 1 rejects an epoch-2 artifact.
	_, epoch2Key, _ := ed25519.GenerateKey(rand.Reader)
	epoch2Signer, _ := passproof.NewSigner(epoch2Key, 2)
	epoch2Artifact, err := epoch2Signer.Sign(passproof.Payload{
		PassID: pass.PassID, ProductID: "prod-val-week", ScopeType: passproof.ScopeNetwork,
		ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(24 * time.Hour),
		HolderDigest: pass.OwnerDigest,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decision := fixture.validation.Validate(ctx, epoch2Artifact, ""); decision.Admit || decision.Reason != "unknown_kid" {
		t.Fatalf("wrong-epoch artifact must DENY unknown_kid, got %+v", decision)
	}

	// Route scope enforcement.
	routePass := fixture.buyPass(t, "prod-val-route", "val-3", "val-purchase-3")
	routeArtifact, _ := fixture.validation.MintArtifact(ctx, routePass.PassID)
	if decision := fixture.validation.Validate(ctx, routeArtifact, "route-a"); !decision.Admit {
		t.Fatalf("in-scope route pass must ADMIT, got %+v", decision)
	}
	if decision := fixture.validation.Validate(ctx, routeArtifact, "route-b"); decision.Admit || decision.Reason != "out_of_scope" {
		t.Fatalf("out-of-scope route pass must DENY out_of_scope, got %+v", decision)
	}
}

func TestBlocklistDeltaPaginationAndSignature(t *testing.T) {
	fixture := newValidationFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.passes.CreatePassProduct(ctx, PassProduct{
		ProductID: "prod-bl", Kind: PassKindDay, ScopeType: ScopeTypeNetwork, PriceNGNMinor: 10000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	revoked := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		pass := fixture.buyPass(t, "prod-bl", fmt.Sprintf("bl-%d", i), fmt.Sprintf("bl-purchase-%d", i))
		if _, err := fixture.passes.Revoke(ctx, pass.PassID, "officer:1", "fraud", "corr-bl"); err != nil {
			t.Fatal(err)
		}
		revoked = append(revoked, pass.PassID)
	}
	// Paginate with limit 2 and verify every page's signature against the
	// cached key directory, as a conductor device would.
	rows, err := fixture.store.ListValidationKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	trusted := make([]passproof.TrustedKey, 0, len(rows))
	for _, row := range rows {
		public, err := hex.DecodeString(row.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, passproof.TrustedKey{KeyID: row.Kid, Public: public, Epoch: uint32(row.Epoch)})
	}
	verifier, err := passproof.NewVerifier(trusted)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	cursor := ""
	sinceUnix := int64(0)
	for page := 0; ; page++ {
		delta, err := fixture.validation.BlocklistDelta(ctx, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		var since int64
		if cursor != "" {
			fmt.Sscanf(cursor, "%d:", &since)
		}
		if err := verifier.VerifyBlocklist(delta.Epoch, since, delta.PassIDs, delta.Signature); err != nil {
			t.Fatalf("page %d signature: %v", page, err)
		}
		if len(delta.PassIDs) == 0 {
			break
		}
		if len(delta.PassIDs) > 2 {
			t.Fatalf("page %d carried %d entries over limit 2", page, len(delta.PassIDs))
		}
		for _, passID := range delta.PassIDs {
			if seen[passID] {
				t.Fatalf("pass %s appeared on two pages", passID)
			}
			seen[passID] = true
		}
		cursor = delta.NextCursor
		sinceUnix = since
		if page > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	_ = sinceUnix
	if len(seen) != 5 {
		t.Fatalf("blocklist delta carried %d entries, expected 5", len(seen))
	}
	for _, passID := range revoked {
		if !seen[passID] {
			t.Fatalf("revoked pass %s missing from blocklist", passID)
		}
	}
}

// --- conductor store-and-forward --------------------------------------------

type conductorFixture struct {
	validationFixture
	keySet    *ticketproof.KeySet
	verifier  *ticketproof.Verifier
	conductor *ConductorService
}

const testWindowSecret = "conductor-window-secret-0123456789"

func newConductorFixture(t *testing.T) conductorFixture {
	t.Helper()
	fixture := newValidationFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keySet, err := ticketproof.NewKeySet(privateKey, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := keySet.Verifier(testWindowSecret)
	if err != nil {
		t.Fatal(err)
	}
	conductor, err := NewConductorService(fixture.store, fixture.ticketStore, verifier, fixture.validation, fixture.accounts)
	if err != nil {
		t.Fatal(err)
	}
	return conductorFixture{fixture, keySet, verifier, conductor}
}

// mintTicketArtifact signs a BET1 artifact for an issued ticket.
func (fixture conductorFixture) mintTicketArtifact(t *testing.T, ticketID, tripID, digest string, seat int, expires time.Time) string {
	t.Helper()
	token, err := fixture.keySet.Sign(ticketproof.Payload{
		TicketID: ticketID, TripID: tripID, Seat: seat,
		IssuedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: expires.UTC(),
		HolderDigest: digest,
	}, testWindowSecret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestConductorBatchIdempotentReplay(t *testing.T) {
	fixture := newConductorFixture(t)
	defer fixture.close()
	ctx := context.Background()

	seedTrip(t, ctx, fixture.pool, "op-cond", "vessel-cond", "trip-cond", "route-cond", 50000, 10)
	ticket, _, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
		TripID: "trip-cond", PassengerRef: "cond-commuter", Channel: ChannelDirect,
		IdempotencyKey: "cond-journey-1", CorrelationID: "corr-cond", Principal: "passenger:cond-commuter",
	})
	if err != nil {
		t.Fatal(err)
	}
	var digestValue string
	if err := fixture.pool.QueryRow(ctx, `SELECT passenger_digest_sha256 FROM tickets WHERE ticket_id = $1`, ticket.TicketID).Scan(&digestValue); err != nil {
		t.Fatal(err)
	}
	trip, err := fixture.ticketStore.GetTrip(ctx, "trip-cond")
	if err != nil {
		t.Fatal(err)
	}
	artifact := fixture.mintTicketArtifact(t, ticket.TicketID, ticket.TripID, digestValue, 1, trip.ScheduledDeparture)

	batch := BatchRequest{
		DeviceID: "device-1", BatchID: "batch-1", OperatorID: "op-cond", BatchSignature: "device-signature-placeholder",
		Principal: "conductor:device-1", CorrelationID: "corr-batch",
		Scans: []BatchScan{{
			ScanID: "scan-1", Artifact: artifact, ScannedAt: time.Now().Add(-time.Minute).UTC(), Signature: "scan-signature",
		}},
	}
	result, err := fixture.conductor.SubmitBatch(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Batch.Admitted != 1 || len(result.Scans) != 1 || result.Scans[0].Result != ScanAdmitted {
		t.Fatalf("first batch result = %+v", result)
	}
	// First-scan-wins: the seat ticket is consumed exactly once.
	var boardedBy string
	if err := fixture.pool.QueryRow(ctx, `SELECT boarded_by FROM tickets WHERE ticket_id = $1`, ticket.TicketID).Scan(&boardedBy); err != nil {
		t.Fatal(err)
	}
	if boardedBy != "device:device-1" {
		t.Fatalf("boarded_by = %q", boardedBy)
	}
	// Replay of the same batch returns the stored outcome, no double admit.
	replay, err := fixture.conductor.SubmitBatch(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Batch.Admitted != 1 || replay.Scans[0].Result != ScanAdmitted {
		t.Fatalf("replay result = %+v", replay)
	}
	var boardingEvents int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM conductor_scans WHERE device_id = 'device-1' AND scan_id = 'scan-1'`).Scan(&boardingEvents); err != nil {
		t.Fatal(err)
	}
	if boardingEvents != 1 {
		t.Fatalf("scan records = %d, expected 1 (durable dedupe)", boardingEvents)
	}
	// A second presentation of the same ticket in a NEW batch is a DUPLICATE,
	// never a second boarding.
	second := batch
	second.BatchID = "batch-2"
	second.Scans = []BatchScan{{ScanID: "scan-2", Artifact: artifact, ScannedAt: time.Now().UTC(), Signature: "scan-signature"}}
	dupe, err := fixture.conductor.SubmitBatch(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if dupe.Scans[0].Result != ScanDuplicate {
		t.Fatalf("second presentation = %+v, expected DUPLICATE", dupe.Scans[0])
	}
	// A tampered artifact denies; a cross-operator presentation routes to REVIEW.
	tampered := artifact[:len(artifact)/2] + "AAAA" + artifact[len(artifact)/2+4:]
	third := batch
	third.BatchID = "batch-3"
	third.Scans = []BatchScan{{ScanID: "scan-3", Artifact: tampered, ScannedAt: time.Now().UTC(), Signature: "s"}}
	denied, err := fixture.conductor.SubmitBatch(ctx, third)
	if err != nil {
		t.Fatal(err)
	}
	if denied.Scans[0].Result != ScanDenied || denied.Scans[0].DenyReason == "" {
		t.Fatalf("tampered scan = %+v, expected DENIED with reason", denied.Scans[0])
	}
	otherOp := batch
	otherOp.BatchID = "batch-4"
	otherOp.OperatorID = "op-other"
	otherOp.Scans = []BatchScan{{ScanID: "scan-4", Artifact: artifact, ScannedAt: time.Now().UTC(), Signature: "s"}}
	review, err := fixture.conductor.SubmitBatch(ctx, otherOp)
	if err != nil {
		t.Fatal(err)
	}
	if review.Scans[0].Result != ScanReviewRequired || review.Scans[0].DenyReason != "cross_operator_presentation" {
		t.Fatalf("cross-operator scan = %+v, expected REVIEW_REQUIRED", review.Scans[0])
	}
	// Batch results are retrievable by (device, batch).
	stored, err := fixture.store.GetConductorBatch(ctx, "device-1", "batch-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProcessedAt == nil || stored.Admitted != 1 {
		t.Fatalf("stored batch = %+v", stored)
	}
}

// --- offline debit: caps, settlement, reconciliation -------------------------

func TestOfflineDebitCapsSettlementAndReplay(t *testing.T) {
	fixture := newConductorFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "offline-rider", ConcessionStandard, "", "agent:1", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpAgentCash, AmountNGNMinor: 100000,
		AgentID: "agent-1", IdempotencyKey: "topup-cash-1", CorrelationID: "corr-topup", Principal: "agent:1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.RegisterInstrument(ctx, account.AccountID, "PHONE_QR", "instrument-token-1", "agent:1", "corr-inst"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetDeviceCaps(ctx, DeviceCaps{
		DeviceID: "device-offline", OperatorID: "op-off", PerTxCapMinor: 30000, DailyCapMinor: 60000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	debitBatch := func(batchID string, scans ...BatchScan) BatchResult {
		t.Helper()
		result, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
			DeviceID: "device-offline", BatchID: batchID, OperatorID: "op-off",
			BatchSignature: "sig", Principal: "conductor:device-offline", Scans: scans,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// Settled within caps.
	first := debitBatch("debit-batch-1", BatchScan{
		ScanID: "debit-1", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 25000, ScannedAt: time.Now().Add(-2 * time.Minute).UTC(), Signature: "s",
	})
	if first.Scans[0].Result != ScanAdmitted {
		t.Fatalf("settled debit = %+v", first.Scans[0])
	}
	// Replay: no double settle, no double ledger debit.
	replay := debitBatch("debit-batch-1", BatchScan{
		ScanID: "debit-1", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 25000, ScannedAt: time.Now().Add(-2 * time.Minute).UTC(), Signature: "s",
	})
	if !replay.Replayed || len(fixture.accounts.debits) != 1 {
		t.Fatalf("replay double-settled: replayed=%v debits=%d", replay.Replayed, len(fixture.accounts.debits))
	}
	// Cached balance moved with the settle.
	view, err := fixture.accountSvc.GetAccountView(ctx, account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if view.CachedBalanceMinor != 75000 || view.FlowBalanceMinor != 75000 || view.CacheDriftMinor != 0 {
		t.Fatalf("account view = %+v", view)
	}
	// Over the per-transaction cap: REVIEW, never settled.
	over := debitBatch("debit-batch-2", BatchScan{
		ScanID: "debit-2", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 40000, ScannedAt: time.Now().UTC(), Signature: "s",
	})
	if over.Scans[0].Result != ScanReviewRequired || over.Scans[0].DenyReason != "over_per_tx_cap" {
		t.Fatalf("over-cap debit = %+v", over.Scans[0])
	}
	if len(fixture.accounts.debits) != 1 {
		t.Fatal("review debit must never reach the ledger")
	}
	// Daily cap 60000: 25000 settled + another 25000 fits; a third breaches.
	debitBatch("debit-batch-3", BatchScan{
		ScanID: "debit-3", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 25000, ScannedAt: time.Now().UTC(), Signature: "s",
	})
	daily := debitBatch("debit-batch-4", BatchScan{
		ScanID: "debit-4", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 25000, ScannedAt: time.Now().UTC(), Signature: "s",
	})
	if daily.Scans[0].Result != ScanReviewRequired || daily.Scans[0].DenyReason != "over_daily_cap" {
		t.Fatalf("daily-cap debit = %+v", daily.Scans[0])
	}
	// Decline-after-sync on a second provisioned device: drain the account
	// below the scan amount; the ledger rejects and the debit lands in the
	// liability queue (never faked).
	if err := fixture.store.SetDeviceCaps(ctx, DeviceCaps{
		DeviceID: "device-offline-b", OperatorID: "op-off", PerTxCapMinor: 30000, DailyCapMinor: 1000000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	debitB := func(batchID string, scans ...BatchScan) BatchResult {
		t.Helper()
		result, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
			DeviceID: "device-offline-b", BatchID: batchID, OperatorID: "op-off",
			BatchSignature: "sig", Principal: "conductor:device-offline-b", Scans: scans,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	drain := debitB("debit-batch-b1", BatchScan{
		ScanID: "debit-5", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 30000, ScannedAt: time.Now().UTC(), Signature: "s",
	})
	if drain.Scans[0].Result != ScanAdmitted {
		t.Fatalf("drain debit = %+v", drain.Scans[0])
	}
	declined := debitB("debit-batch-b2", BatchScan{
		ScanID: "debit-6", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
		AmountNGNMinor: 25000, ScannedAt: time.Now().UTC(), Signature: "s",
	})
	if declined.Scans[0].Result != ScanDenied || declined.Scans[0].DenyReason != "debit_declined" {
		t.Fatalf("declined debit = %+v", declined.Scans[0])
	}
	// Reconciliation report: settled 70000, declined 25000 (liability), review 65000.
	from := time.Now().Add(-time.Hour)
	reports, err := fixture.store.OfflineDebitReconciliation(ctx, from, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	totals := OfflineDebitReport{}
	for _, report := range reports {
		totals.SettledMinor += report.SettledMinor
		totals.DeclinedMinor += report.DeclinedMinor
		totals.ReviewMinor += report.ReviewMinor
	}
	if totals.SettledMinor != 80000 || totals.DeclinedMinor != 25000 || totals.ReviewMinor != 65000 {
		t.Fatalf("reconciliation = %+v, expected settled 80000 / declined 25000 / review 65000", reports)
	}
	// Unprovisioned device fails closed.
	rogue, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
		DeviceID: "device-rogue", BatchID: "rogue-1", OperatorID: "op-off", BatchSignature: "sig",
		Principal: "conductor:rogue",
		Scans: []BatchScan{{ScanID: "rogue-scan", Kind: "ACCOUNT_DEBIT", Artifact: "instrument-token-1",
			AmountNGNMinor: 1000, ScannedAt: time.Now().UTC(), Signature: "s"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rogue.Scans[0].Result != ScanDenied || rogue.Scans[0].DenyReason != "device_not_provisioned" {
		t.Fatalf("unprovisioned device = %+v, expected DENIED device_not_provisioned", rogue.Scans[0])
	}
}

// --- top-up state machine ----------------------------------------------------

func signWebhook(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestTopUpStateMachineAndWebhookReplay(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "nip-rider", ConcessionStandard, "", "passenger:nip-rider", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	topup, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 50000,
		IdempotencyKey: "nip-topup-1", CorrelationID: "corr-nip", Principal: "passenger:nip-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if topup.State != TopUpPending || topup.Reference == "" {
		t.Fatalf("top-up = %+v, expected PENDING with reference", topup)
	}
	// Nothing credited before the rail confirms.
	if len(fixture.accounts.credits) != 0 {
		t.Fatal("pending top-up must not credit the ledger")
	}
	// Idempotent initiate replay.
	again, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 50000,
		IdempotencyKey: "nip-topup-1", CorrelationID: "corr-nip", Principal: "passenger:nip-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.TopUpID != topup.TopUpID {
		t.Fatal("initiate replay must return the original top-up")
	}
	// Bad HMAC fails closed.
	body := []byte(`{"reference":"` + topup.Reference + `","externalRef":"nip-txn-1","amountNgnMinor":50000,"status":"SUCCESS"}`)
	if err := fixture.accountSvc.VerifyWebhookSignature(body, "deadbeef"); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("bad signature must fail closed, got %v", err)
	}
	if err := fixture.accountSvc.VerifyWebhookSignature(body, signWebhook("wrong-secret", body)); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("wrong-secret signature must fail closed, got %v", err)
	}
	// Verified webhook credits exactly once.
	if err := fixture.accountSvc.VerifyWebhookSignature(body, signWebhook(testWebhookSecret, body)); err != nil {
		t.Fatal(err)
	}
	credited, err := fixture.accountSvc.HandleRailWebhook(ctx, RailWebhook{
		Reference: topup.Reference, ExternalRef: "nip-txn-1", AmountMinor: 50000, Status: "SUCCESS",
	}, "corr-webhook")
	if err != nil {
		t.Fatal(err)
	}
	if credited.State != TopUpCredited || credited.ExternalRef != "nip-txn-1" {
		t.Fatalf("credited top-up = %+v", credited)
	}
	if len(fixture.accounts.credits) != 1 || fixture.accounts.credits[0].source != ledger.FundingPassengerClearing {
		t.Fatalf("ledger credits = %+v", fixture.accounts.credits)
	}
	// Webhook replay: no second credit, state stays CREDITED.
	replayed, err := fixture.accountSvc.HandleRailWebhook(ctx, RailWebhook{
		Reference: topup.Reference, ExternalRef: "nip-txn-1", AmountMinor: 50000, Status: "SUCCESS",
	}, "corr-webhook-2")
	if err != nil {
		t.Fatal(err)
	}
	if replayed.State != TopUpCredited || len(fixture.accounts.credits) != 1 {
		t.Fatalf("webhook replay double-credited: %+v", replayed)
	}
	// Amount mismatch is rejected before any movement (fresh pending top-up).
	mismatch, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNIPTransfer, AmountNGNMinor: 30000,
		IdempotencyKey: "nip-topup-2", CorrelationID: "corr-nip-2", Principal: "passenger:nip-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.HandleRailWebhook(ctx, RailWebhook{
		Reference: mismatch.Reference, ExternalRef: "nip-txn-2", AmountMinor: 1, Status: "SUCCESS",
	}, "corr-webhook-3"); err == nil {
		t.Fatal("amount-mismatched webhook must reject")
	}
	if len(fixture.accounts.credits) != 1 {
		t.Fatal("mismatched webhook must not credit")
	}
	// Cached balance matches the flow.
	view, err := fixture.accountSvc.GetAccountView(ctx, account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if view.CachedBalanceMinor != 50000 || view.CacheDriftMinor != 0 {
		t.Fatalf("view = %+v", view)
	}
	// FAILED rail outcome marks the top-up failed, never credits.
	failedTopup, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpMojaloop, AmountNGNMinor: 10000,
		IdempotencyKey: "moj-topup-1", CorrelationID: "corr-moj", Principal: "passenger:nip-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := fixture.accountSvc.HandleRailWebhook(ctx, RailWebhook{
		Reference: failedTopup.Reference, ExternalRef: "moj-txn-1", AmountMinor: 10000, Status: "FAILED",
	}, "corr-moj-webhook")
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != TopUpFailed || len(fixture.accounts.credits) != 1 {
		t.Fatalf("failed top-up = %+v", failed)
	}
}

func TestNQRPayloadStructure(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "nqr-rider", ConcessionStandard, "", "passenger:nqr-rider", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	topup, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpNQR, AmountNGNMinor: 250000,
		IdempotencyKey: "nqr-topup-1", CorrelationID: "corr-nqr", Principal: "passenger:nqr-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NQRPayload(topup, "BLUEFARE TOPUP")
	if err != nil {
		t.Fatal(err)
	}
	// EMV structure: format indicator, dynamic POI, NGN currency, amount in
	// naira, the reconciliation reference, and a valid CRC16 trailer.
	for _, fragment := range []string{"000201", "010212", "5303566", "54072500.00", "5802NG", "5914BLUEFARE TOPUP"} {
		if !contains(payload, fragment) {
			t.Fatalf("payload missing %s: %s", fragment, payload)
		}
	}
	if !contains(payload, topup.Reference) {
		t.Fatalf("payload missing reference %s", topup.Reference)
	}
	crcAt := len(payload) - 4
	if payload[crcAt-4:crcAt] != "6304" {
		t.Fatalf("payload missing CRC marker: %s", payload)
	}
	var want uint16
	if _, err := fmt.Sscanf(payload[crcAt:], "%04X", &want); err != nil {
		t.Fatal(err)
	}
	if got := crc16CCITT(payload[:crcAt]); got != want {
		t.Fatalf("CRC mismatch: payload %04X computed %04X", want, got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// --- best-fare, transfer windows, subsidy, settlement -------------------------

func TestBestFareAdjustment(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	// Daily cap 120000, weekly NETWORK pass at 300000: four capped days of
	// spend (480000) exceed the pass price — the difference settles back.
	if err := fixture.store.CreateCapRule(ctx, CapRule{
		RuleID: "cap-bf-day", PeriodKind: "DAY", CapMinor: 120000, ScopeType: ScopeTypeNetwork, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.CreateCapRule(ctx, CapRule{
		RuleID: "cap-bf-week", PeriodKind: "WEEK", CapMinor: 900000, ScopeType: ScopeTypeNetwork, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.passes.CreatePassProduct(ctx, PassProduct{
		ProductID: "prod-bf-week", Kind: PassKindWeek, ScopeType: ScopeTypeNetwork, PriceNGNMinor: 300000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	account, err := fixture.accountSvc.OpenAccount(ctx, "bf-rider", ConcessionStandard, "", "passenger:bf-rider", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	seedTrip(t, ctx, fixture.pool, "op-bf", "vessel-bf", "trip-bf", "route-bf", 120000, 10)
	// Four journeys at 120000 hit the daily cap each "day" — here same-day,
	// so only the first is full price; instead simulate accumulated weekly
	// spend by writing the accumulator directly at 480000.
	weekStart := WeekPeriodStart(time.Now())
	if _, err := fixture.pool.Exec(ctx,
		`INSERT INTO fare_cap_accumulators (subject_ref, period_kind, period_start, scope_type, scope_ref, spent_ngn_minor)
		 VALUES ($1, 'WEEK', $2, 'NETWORK', '', 480000)`, account.AccountID, weekStart); err != nil {
		t.Fatal(err)
	}
	settled, err := fixture.settlement.SettleBestFare(ctx, weekStart, "corr-bf")
	if err != nil {
		t.Fatal(err)
	}
	if settled != 1 {
		t.Fatalf("settled = %d, expected 1", settled)
	}
	// Adjustment = 480000 - 300000 = 180000 refunded to the fare account.
	if len(fixture.accounts.refunds) != 1 || fixture.accounts.refunds[0].amount != 180000 {
		t.Fatalf("best-fare refunds = %+v", fixture.accounts.refunds)
	}
	var adjustment int64
	if err := fixture.pool.QueryRow(ctx,
		`SELECT adjustment_minor FROM best_fare_adjustments WHERE subject_ref = $1 AND period_start = $2`,
		account.AccountID, weekStart).Scan(&adjustment); err != nil {
		t.Fatal(err)
	}
	if adjustment != 180000 {
		t.Fatalf("adjustment = %d, expected 180000", adjustment)
	}
	// Exactly-once: a second settlement of the same period is a no-op.
	settled, err = fixture.settlement.SettleBestFare(ctx, weekStart, "corr-bf-2")
	if err != nil {
		t.Fatal(err)
	}
	if settled != 0 || len(fixture.accounts.refunds) != 1 {
		t.Fatalf("best-fare settlement must be exactly-once, settled=%d refunds=%d", settled, len(fixture.accounts.refunds))
	}
}

func TestTransferWindowDiscount(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.store.CreateFareRule(ctx, FareRule{
		RuleID: "rule-transfer", Kind: "TRANSFER_WINDOW", RouteGroup: "lagos-lagoon",
		WindowMinutes: 60, DiscountPercent: 50, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"route-leg-1", "route-leg-2"} {
		if err := fixture.store.AddRouteGroupMember(ctx, route, "lagos-lagoon"); err != nil {
			t.Fatal(err)
		}
	}
	seedTrip(t, ctx, fixture.pool, "op-tr", "vessel-tr", "trip-leg-1", "route-leg-1", 40000, 10)
	seedTrip(t, ctx, fixture.pool, "op-tr", "vessel-tr", "trip-leg-2", "route-leg-2", 40000, 10)

	first, firstJourney, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
		TripID: "trip-leg-1", PassengerRef: "transfer-rider", Channel: ChannelDirect,
		IdempotencyKey: "transfer-1", CorrelationID: "corr-tr", Principal: "passenger:transfer-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = first
	if firstJourney.ChargedMinor != 40000 || firstJourney.PricingClass != PricingStandard {
		t.Fatalf("first leg = %+v, expected full STANDARD fare", firstJourney)
	}
	_, secondJourney, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
		TripID: "trip-leg-2", PassengerRef: "transfer-rider", Channel: ChannelDirect,
		IdempotencyKey: "transfer-2", CorrelationID: "corr-tr", Principal: "passenger:transfer-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondJourney.ChargedMinor != 20000 || secondJourney.PricingClass != PricingTransfer {
		t.Fatalf("second leg = %+v, expected 50%% TRANSFER fare", secondJourney)
	}
	// A rider without a prior leg pays full fare on leg 2.
	_, coldJourney, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
		TripID: "trip-leg-2", PassengerRef: "cold-rider", Channel: ChannelDirect,
		IdempotencyKey: "transfer-cold", CorrelationID: "corr-tr", Principal: "passenger:cold-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if coldJourney.ChargedMinor != 40000 {
		t.Fatalf("cold rider = %+v, expected full fare", coldJourney)
	}
}

func TestSubsidyReportAndOperatorSettlement(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.store.CreateCapRule(ctx, CapRule{
		RuleID: "cap-sub-day", PeriodKind: "DAY", CapMinor: 50000, ScopeType: ScopeTypeNetwork, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedTrip(t, ctx, fixture.pool, "op-settle", "vessel-settle", "trip-settle", "route-settle", 30000, 10)
	// Three journeys: 30000 + 20000 (capped) + 0 -> gross 50000, subsidy 40000.
	for i := 0; i < 3; i++ {
		if _, _, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
			TripID: "trip-settle", PassengerRef: "settle-rider", Channel: ChannelDirect,
			IdempotencyKey: fmt.Sprintf("settle-journey-%d", i), CorrelationID: "corr-settle",
			Principal: "passenger:settle-rider",
		}); err != nil {
			t.Fatal(err)
		}
	}
	from := time.Now().Add(-time.Hour).Truncate(24 * time.Hour)
	to := from.Add(48 * time.Hour)
	// Subsidy report: standard 90000, charged 50000, subsidy 40000.
	lines, err := fixture.settlement.Subsidy(ctx, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0].RouteReference != "route-settle" {
		t.Fatalf("subsidy lines = %+v", lines)
	}
	if lines[0].StandardMinor != 90000 || lines[0].ChargedMinor != 50000 || lines[0].SubsidyMinor != 40000 {
		t.Fatalf("subsidy math = %+v, expected 90000/50000/40000", lines[0])
	}
	// Settlement: 80/20 split of the 50000 gross.
	if err := fixture.store.UpsertSettlementRule(ctx, SettlementRule{
		OperatorID: "op-settle", OperatorShareBps: 8000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	run, err := fixture.settlement.Run(ctx, "op-settle", from, to, "officer:settlement", "corr-run")
	if err != nil {
		t.Fatal(err)
	}
	if run.GrossMinor != 50000 || run.OperatorMinor != 40000 || run.PlatformMinor != 10000 {
		t.Fatalf("settlement run = %+v, expected gross 50000 / op 40000 / platform 10000", run)
	}
	if run.Rides != 3 {
		t.Fatalf("rides = %d, expected 3", run.Rides)
	}
	if len(fixture.accounts.settlements) != 1 {
		t.Fatalf("linked settlements = %+v", fixture.accounts.settlements)
	}
	call := fixture.accounts.settlements[0]
	if call.share != 40000 || call.platform != 10000 {
		t.Fatalf("linked settlement legs = %+v", call)
	}
	// Exactly-once per period: a re-run returns the recorded run.
	again, err := fixture.settlement.Run(ctx, "op-settle", from, to, "officer:settlement", "corr-run-2")
	if err != nil {
		t.Fatal(err)
	}
	if again.RunID != run.RunID || len(fixture.accounts.settlements) != 1 {
		t.Fatal("settlement must execute exactly once per period")
	}
	// Read-only report matches the executed run.
	report, err := fixture.settlement.Report(ctx, "op-settle", from, to)
	if err != nil {
		t.Fatal(err)
	}
	if report.GrossMinor != 50000 || report.OperatorMinor != 40000 || report.PlatformMinor != 10000 || report.SubsidyMinor != 40000 {
		t.Fatalf("settlement report = %+v", report)
	}
}

// TestConcessionRuleApplied verifies encoded concession discounts.
func TestConcessionRuleApplied(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.store.CreateFareRule(ctx, FareRule{
		RuleID: "rule-student", Kind: "CONCESSION", ConcessionClass: ConcessionStudent,
		DiscountPercent: 25, EligibilityReference: "LAGEDU-ID-VERIFY-v1", Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedTrip(t, ctx, fixture.pool, "op-con", "vessel-con", "trip-con", "route-con", 40000, 10)
	// Concession without an eligibility reference fails closed.
	if _, err := fixture.accountSvc.OpenAccount(ctx, "student-rider", ConcessionStudent, "", "agent:1", "corr"); err == nil {
		t.Fatal("concession account without eligibility reference must fail closed")
	}
	account, err := fixture.accountSvc.OpenAccount(ctx, "student-rider", ConcessionStudent, "student-id-card-991", "agent:1", "corr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpAgentCash, AmountNGNMinor: 100000,
		AgentID: "agent-1", IdempotencyKey: "con-topup", CorrelationID: "corr", Principal: "agent:1",
	}); err != nil {
		t.Fatal(err)
	}
	_, journey, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
		TripID: "trip-con", PassengerRef: "student-rider", Channel: ChannelAccount, AccountID: account.AccountID,
		IdempotencyKey: "con-journey", CorrelationID: "corr", Principal: "passenger:student-rider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if journey.ChargedMinor != 30000 || journey.PricingClass != PricingConcession {
		t.Fatalf("concession journey = %+v, expected 30000 CONCESSION", journey)
	}
	// The account was debited through the account reserve path, not clearing.
	if len(fixture.accounts.reserves) != 1 || fixture.accounts.reserves[0].amount != 30000 {
		t.Fatalf("account reserves = %+v", fixture.accounts.reserves)
	}
	if len(fixture.tickets.reserves) != 0 {
		t.Fatal("account journey must not touch the clearing reserve path")
	}
}
