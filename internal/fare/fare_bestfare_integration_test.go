//go:build integration

package fare

import (
	"context"
	"sync"
	"testing"
	"time"
)

// PRA-137: route-scoped best-fare — per-route guarantees, single most
// favorable payout per subject per week, concurrency-exact.
func TestRouteScopedBestFare(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	// Products: NETWORK week 300000; route-a week 200000 (cheaper for the
	// route commuter); route-b has NO week product (no guarantee).
	for _, product := range []PassProduct{
		{ProductID: "prod-net-week", Kind: PassKindWeek, ScopeType: ScopeTypeNetwork, PriceNGNMinor: 300000, Active: true},
		{ProductID: "prod-route-a-week", Kind: PassKindWeek, ScopeType: ScopeTypeRoute, ScopeRef: "route-a", PriceNGNMinor: 200000, Active: true},
	} {
		if err := fixture.passes.CreatePassProduct(ctx, product); err != nil {
			t.Fatal(err)
		}
	}
	weekStart := WeekPeriodStart(time.Now())
	seed := func(subject, scopeType, scopeRef string, spent int64) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx,
			`INSERT INTO fare_cap_accumulators (subject_ref, period_kind, period_start, scope_type, scope_ref, spent_ngn_minor)
			 VALUES ($1, 'WEEK', $2, $3, $4, $5)`, subject, weekStart, scopeType, scopeRef, spent); err != nil {
			t.Fatal(err)
		}
	}
	// Subject 1: 500000 on route-a (and NETWORK). Route guarantee (300000)
	// beats the network guarantee (200000) — the route scope must win.
	seed("subject-route", "NETWORK", "", 500000)
	seed("subject-route", "ROUTE", "route-a", 500000)
	// Subject 2: 400000 network-wide but only 100000 on route-a — the
	// NETWORK guarantee (100000) is the best outcome.
	seed("subject-net", "NETWORK", "", 400000)
	seed("subject-net", "ROUTE", "route-a", 100000)
	// Subject 3: spend on route-b only; no route-b pass and no NETWORK
	// accumulator row -> no guarantee settles.
	seed("subject-none", "ROUTE", "route-b", 900000)

	settled, err := fixture.settlement.SettleBestFare(ctx, weekStart, "corr-rbf")
	if err != nil {
		t.Fatal(err)
	}
	if settled != 2 {
		t.Fatalf("settled = %d, want 2", settled)
	}
	// Subject 1: route-a scope won, refund 300000.
	var scopeType, scopeRef, productID string
	var adjustment int64
	if err := fixture.pool.QueryRow(ctx,
		`SELECT scope_type, scope_ref, product_id, adjustment_minor FROM best_fare_adjustments
		 WHERE subject_ref = 'subject-route' AND period_start = $1`, weekStart).
		Scan(&scopeType, &scopeRef, &productID, &adjustment); err != nil {
		t.Fatal(err)
	}
	if scopeType != "ROUTE" || scopeRef != "route-a" || productID != "prod-route-a-week" || adjustment != 300000 {
		t.Fatalf("subject-route adjustment = %s/%s/%s/%d, want ROUTE/route-a/prod-route-a-week/300000",
			scopeType, scopeRef, productID, adjustment)
	}
	// Subject 2: NETWORK scope won, refund 100000.
	if err := fixture.pool.QueryRow(ctx,
		`SELECT scope_type, adjustment_minor FROM best_fare_adjustments
		 WHERE subject_ref = 'subject-net' AND period_start = $1`, weekStart).
		Scan(&scopeType, &adjustment); err != nil {
		t.Fatal(err)
	}
	if scopeType != "NETWORK" || adjustment != 100000 {
		t.Fatalf("subject-net adjustment = %s/%d, want NETWORK/100000", scopeType, adjustment)
	}
	// Subject 3: nothing.
	var rows int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM best_fare_adjustments WHERE subject_ref = 'subject-none'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("subject without a covering product must not settle")
	}
	// Two ticket-only subjects -> two clearing refunds, exactly the winners.
	if len(fixture.tickets.refunds) != 2 {
		t.Fatalf("ticket refunds = %+v", fixture.tickets.refunds)
	}
	amounts := map[string]bool{}
	for _, refund := range fixture.tickets.refunds {
		amounts[refund.ref] = true
	}
	if !amounts["bestfare:subject-route:"+weekStart.Format("2006-01-02")+":ROUTE:route-a"] ||
		!amounts["bestfare:subject-net:"+weekStart.Format("2006-01-02")+":NETWORK:"] {
		t.Fatalf("refund references = %+v", fixture.tickets.refunds)
	}
	// Re-run is a no-op (exactly-once per subject per week).
	settled, err = fixture.settlement.SettleBestFare(ctx, weekStart, "corr-rbf-2")
	if err != nil {
		t.Fatal(err)
	}
	if settled != 0 || len(fixture.tickets.refunds) != 2 {
		t.Fatalf("re-settle moved value: settled=%d refunds=%d", settled, len(fixture.tickets.refunds))
	}
}

// TestRouteScopedBestFareConcurrent races two settlement runs against a
// second week: the money and the record must stay exactly-once.
func TestRouteScopedBestFareConcurrent(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.passes.CreatePassProduct(ctx, PassProduct{
		ProductID: "prod-race-week", Kind: PassKindWeek, ScopeType: ScopeTypeRoute, ScopeRef: "route-race",
		PriceNGNMinor: 100000, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	weekStart := WeekPeriodStart(time.Now().Add(-7 * 24 * time.Hour))
	if _, err := fixture.pool.Exec(ctx,
		`INSERT INTO fare_cap_accumulators (subject_ref, period_kind, period_start, scope_type, scope_ref, spent_ngn_minor)
		 VALUES ('subject-race', 'WEEK', $1, 'ROUTE', 'route-race', 450000)`, weekStart); err != nil {
		t.Fatal(err)
	}
	const racers = 8
	var wait sync.WaitGroup
	errs := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := fixture.settlement.SettleBestFare(ctx, weekStart, "corr-race")
			errs <- err
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent settle: %v", err)
		}
	}
	if len(fixture.tickets.refunds) != 1 || fixture.tickets.refunds[0].amount != 350000 {
		t.Fatalf("refunds = %+v, want exactly one 350000", fixture.tickets.refunds)
	}
	var rows int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM best_fare_adjustments WHERE subject_ref = 'subject-race'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("adjustment rows = %d, want 1", rows)
	}
}
