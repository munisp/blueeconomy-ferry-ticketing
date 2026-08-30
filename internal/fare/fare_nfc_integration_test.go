//go:build integration

package fare

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

// PRA-133 integration: enrolled tap settles as a capped offline debit;
// replayed counters, bad signatures and unenrolled paths fail closed.
func TestNFCTapAcceptance(t *testing.T) {
	fixture := newConductorFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "tap-rider", ConcessionStandard, "", "agent:1", "corr-open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpAgentCash, AmountNGNMinor: 100000,
		AgentID: "agent-1", IdempotencyKey: "tap-topup", CorrelationID: "corr", Principal: "agent:1",
	}); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(publicKey)
	if _, err := fixture.accountSvc.RegisterTapInstrument(ctx, account.AccountID, "tap-token-1", keyHex, "agent:1", "corr-enroll"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetDeviceCaps(ctx, DeviceCaps{
		DeviceID: "device-tap", OperatorID: "op-tap", PerTxCapMinor: 30000, DailyCapMinor: 60000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	submit := func(batchID string, scan BatchScan) BatchResult {
		t.Helper()
		result, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
			DeviceID: "device-tap", BatchID: batchID, OperatorID: "op-tap",
			BatchSignature: "sig", Principal: "conductor:device-tap", Scans: []BatchScan{scan},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// Valid tap settles through the capped offline-debit path.
	tap1, err := EncodeTapPayload(privateKey, "tap-token-1", 25000, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	first := submit("tap-batch-1", BatchScan{ScanID: "tap-scan-1", Kind: "NFC_TAP", Artifact: tap1, ScannedAt: time.Now().UTC(), Signature: "s"})
	if first.Scans[0].Result != ScanAdmitted {
		t.Fatalf("valid tap = %+v, want ADMITTED", first.Scans[0])
	}
	if len(fixture.accounts.debits) != 1 || fixture.accounts.debits[0].amount != 25000 {
		t.Fatalf("ledger debits = %+v", fixture.accounts.debits)
	}
	// Replayed counter (cloned payload re-uploaded under a NEW scan id)
	// denies: the monotonic counter was spent.
	second := submit("tap-batch-2", BatchScan{ScanID: "tap-scan-2", Kind: "NFC_TAP", Artifact: tap1, ScannedAt: time.Now().UTC(), Signature: "s"})
	if second.Scans[0].Result != ScanDenied || second.Scans[0].DenyReason != "tap_replayed" {
		t.Fatalf("replayed tap = %+v, want DENIED tap_replayed", second.Scans[0])
	}
	if len(fixture.accounts.debits) != 1 {
		t.Fatal("replayed tap must never reach the ledger")
	}
	// Tampered signature denies.
	tamperedPayload, err := ParseTapPayload(tap1)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload.Counter = 2
	forged, err := EncodeTapPayload(privateKey, "tap-token-1", 25000, 2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// Flip the signature bytes of a well-formed payload.
	forgedRaw, _ := base64.RawURLEncoding.DecodeString(forged)
	forgedRaw[len(forgedRaw)-1] ^= 0xFF
	forgedTampered := base64.RawURLEncoding.EncodeToString(forgedRaw)
	_ = tamperedPayload
	third := submit("tap-batch-3", BatchScan{ScanID: "tap-scan-3", Kind: "NFC_TAP", Artifact: forgedTampered, ScannedAt: time.Now().UTC(), Signature: "s"})
	if third.Scans[0].Result != ScanDenied || third.Scans[0].DenyReason != "invalid_tap_signature" {
		t.Fatalf("tampered tap = %+v, want DENIED invalid_tap_signature", third.Scans[0])
	}
	// Over-cap tap routes to REVIEW (same capped semantics as offline debit).
	big, err := EncodeTapPayload(privateKey, "tap-token-1", 45000, 3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	fourth := submit("tap-batch-4", BatchScan{ScanID: "tap-scan-4", Kind: "NFC_TAP", Artifact: big, ScannedAt: time.Now().UTC(), Signature: "s"})
	if fourth.Scans[0].Result != ScanReviewRequired || fourth.Scans[0].DenyReason != "over_per_tx_cap" {
		t.Fatalf("over-cap tap = %+v, want REVIEW over_per_tx_cap", fourth.Scans[0])
	}
	// Unprovisioned device fails closed even with a perfect tap (fresh
	// counter, so the denial comes from the device plane, not replay).
	rogueTap, err := EncodeTapPayload(privateKey, "tap-token-1", 1000, 4, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
		DeviceID: "device-rogue-tap", BatchID: "rogue-tap-1", OperatorID: "op-tap", BatchSignature: "sig",
		Principal: "conductor:rogue",
		Scans: []BatchScan{{ScanID: "rogue-tap-scan", Kind: "NFC_TAP", Artifact: rogueTap, ScannedAt: time.Now().UTC(), Signature: "s"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rogue.Scans[0].Result != ScanDenied || rogue.Scans[0].DenyReason != "device_not_provisioned" {
		t.Fatalf("rogue device tap = %+v", rogue.Scans[0])
	}
	// Account view reflects the settled tap with zero drift.
	view, err := fixture.accountSvc.GetAccountView(ctx, account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if view.OfflineDebitMinor != 25000 || view.CachedBalanceMinor != 75000 || view.CacheDriftMinor != 0 {
		t.Fatalf("view = %+v", view)
	}
}
