//go:build integration

package fare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// PRA-135 integration: registry lifecycle is authoritative when fresh;
// stale registry falls back to the local fail-closed plane.
func TestConductorDeviceRegistryLifecycle(t *testing.T) {
	fixture := newConductorFixture(t)
	defer fixture.close()
	ctx := context.Background()

	account, err := fixture.accountSvc.OpenAccount(ctx, "reg-rider", ConcessionStandard, "", "agent:1", "corr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.TopUp(ctx, TopUpRequest{
		AccountID: account.AccountID, Channel: TopUpAgentCash, AmountNGNMinor: 50000,
		AgentID: "agent-1", IdempotencyKey: "reg-topup", CorrelationID: "corr", Principal: "agent:1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.accountSvc.RegisterInstrument(ctx, account.AccountID, "PHONE_QR", "reg-token-1", "agent:1", "corr"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetDeviceCaps(ctx, DeviceCaps{
		DeviceID: "device-reg", OperatorID: "op-reg", PerTxCapMinor: 30000, DailyCapMinor: 60000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	status := "ACTIVE"
	registry := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(RegistryDevice{ID: "device-reg", Kind: "CONDUCTOR", Status: status, KeyEpoch: 1})
	}))
	defer registry.Close()
	client, err := NewDeviceRegistryClient(registry.URL, "service-token-123", registry.Client())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewDeviceDirectory(client, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	fixture.conductor.WithDeviceDirectory(directory)
	submit := func(batchID string) BatchResult {
		t.Helper()
		result, err := fixture.conductor.SubmitBatch(ctx, BatchRequest{
			DeviceID: "device-reg", BatchID: batchID, OperatorID: "op-reg", BatchSignature: "sig",
			Principal: "conductor:device-reg",
			Scans: []BatchScan{{ScanID: batchID + "-scan", Kind: "ACCOUNT_DEBIT", Artifact: "reg-token-1",
				AmountNGNMinor: 10000, ScannedAt: time.Now().UTC(), Signature: "s"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// ACTIVE in the registry + local caps: settles.
	if result := submit("reg-batch-1"); result.Scans[0].Result != ScanAdmitted {
		t.Fatalf("active device = %+v, want ADMITTED", result.Scans[0])
	}
	// SUSPENDED in the registry: denied even though local caps exist
	// (fresh registry verdict is authoritative for lifecycle).
	time.Sleep(60 * time.Millisecond) // past cache TTL: lifecycle re-read
	status = "SUSPENDED"
	if result := submit("reg-batch-2"); result.Scans[0].Result != ScanDenied || result.Scans[0].DenyReason != "device_suspended" {
		t.Fatalf("suspended device = %+v, want DENIED device_suspended", result.Scans[0])
	}
	// Registry unreachable with a stale cache: explicit fallback to the
	// local fail-closed plane — the stale ACTIVE verdict does not override
	// anything, local caps still govern.
	status = "ACTIVE"
	staleDir, err := NewDeviceDirectory(client, time.Millisecond) // ~immediately stale
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleDir.Lookup(ctx, "device-reg"); err != nil { // prime cache
		t.Fatal(err)
	}
	registry.Close()
	time.Sleep(5 * time.Millisecond)
	fixture.conductor.WithDeviceDirectory(staleDir)
	if result := submit("reg-batch-3"); result.Scans[0].Result != ScanAdmitted {
		t.Fatalf("stale-registry fallback = %+v, want local-plane ADMITTED", result.Scans[0])
	}
	// Registry unreachable with NO cache at all: fail closed.
	coldDir, err := NewDeviceDirectory(client, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fixture.conductor.WithDeviceDirectory(coldDir)
	if result := submit("reg-batch-4"); result.Scans[0].Result != ScanDenied || result.Scans[0].DenyReason != "device_registry_unreachable" {
		t.Fatalf("cold unreachable registry = %+v, want DENIED device_registry_unreachable", result.Scans[0])
	}
}
