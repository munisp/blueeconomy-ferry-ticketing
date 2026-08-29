//go:build integration

package fare

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// Integration harness: real PostgreSQL (the same ferry_test database and
// migration chain as the ticketing suite), fake ledgers recording every op
// so tests assert accumulator/ledger consistency without a TigerBeetle
// cluster (TB cannot run in this sandbox; the ledger mapping itself is
// covered by the ledger package's TB-tagged suite).

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("FERRY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("FERRY_TEST_DATABASE_URL is required for integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	migrationsDir := filepath.Join("..", "..", "db", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		statement, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, string(statement)); err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
	return pool
}

func seedTrip(t *testing.T, ctx context.Context, pool *pgxpool.Pool, operatorID, vesselID, tripID, routeRef string, fareMinor int64, capacity int) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO operators (operator_id, registered_name) VALUES ($1, $2) ON CONFLICT (operator_id) DO NOTHING`,
		operatorID, "Fare Integration Operator"); err != nil {
		t.Fatalf("insert operator: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO vessels (vessel_id, operator_id, vessel_name, capacity) VALUES ($1, $2, $3, 100) ON CONFLICT (vessel_id) DO NOTHING`,
		vesselID, operatorID, "Fare Integration Vessel"); err != nil {
		t.Fatalf("insert vessel: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO trips (trip_id, vessel_id, operator_id, route_reference, terminal_reference, scheduled_departure, fare_ngn_minor, capacity)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tripID, vesselID, operatorID, routeRef, "terminal-fare", time.Now().Add(24*time.Hour).UTC(), fareMinor, capacity); err != nil {
		t.Fatalf("insert trip: %v", err)
	}
}

// --- fake ledgers -----------------------------------------------------------

type reserveCall struct {
	ref     string
	channel ticketing.Channel
	amount  int64
}

type fakeTicketLedger struct {
	mu       sync.Mutex
	reserves []reserveCall
	posts    []string
	voids    []string
	refunds  []reserveCall
}

func (fake *fakeTicketLedger) Reserve(_ context.Context, ref string, channel ticketing.Channel, amount int64) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.reserves = append(fake.reserves, reserveCall{ref, channel, amount})
	return "rsv-" + ref, nil
}

func (fake *fakeTicketLedger) Post(_ context.Context, reserveID string) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.posts = append(fake.posts, reserveID)
	return "post-" + reserveID, nil
}

func (fake *fakeTicketLedger) Void(_ context.Context, reserveID string) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.voids = append(fake.voids, reserveID)
	return nil
}

func (fake *fakeTicketLedger) Refund(_ context.Context, ref string, amount int64) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.refunds = append(fake.refunds, reserveCall{ref: ref, amount: amount})
	return "rfnd-" + ref, nil
}

func (fake *fakeTicketLedger) ResolveReserve(_ context.Context, reserveID string) (ticketing.ReserveResolution, error) {
	return ticketing.ReserveResolution{Status: ticketing.ReserveStatusPosted, PostTransferID: "post-" + reserveID}, nil
}

type accountCall struct {
	ref       string
	accountID string
	amount    int64
	source    ledger.FundingSource
}

type settlementCall struct {
	runID     string
	wallet    string
	share     int64
	platform  int64
}

// fakeAccountLedger simulates the cluster balance rule
// (DEBITS_MUST_NOT_EXCEED_CREDITS) so decline-after-sync is testable.
type fakeAccountLedger struct {
	mu          sync.Mutex
	balances    map[string]int64
	ensures     []string
	reserves    []accountCall
	credits     []accountCall
	debits      []accountCall
	refunds     []accountCall
	settlements []settlementCall
}

func newFakeAccountLedger() *fakeAccountLedger {
	return &fakeAccountLedger{balances: map[string]int64{}}
}

func (fake *fakeAccountLedger) EnsureAccount(id tigerbeetle.Uint128, _ bool) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.ensures = append(fake.ensures, id.String())
	return nil
}

func (fake *fakeAccountLedger) ReserveFromAccount(_ context.Context, ref, accountID string, amount int64) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.balances[accountID] < amount {
		return "", errors.New("cluster rejected: exceeds credits")
	}
	fake.balances[accountID] -= amount
	fake.reserves = append(fake.reserves, accountCall{ref: ref, accountID: accountID, amount: amount})
	return "arsv-" + ref, nil
}

func (fake *fakeAccountLedger) CreditAccount(_ context.Context, ref, accountID string, amount int64, source ledger.FundingSource) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.balances[accountID] += amount
	fake.credits = append(fake.credits, accountCall{ref: ref, accountID: accountID, amount: amount, source: source})
	return "cr-" + ref, nil
}

func (fake *fakeAccountLedger) DebitAccount(_ context.Context, ref, accountID string, amount int64) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.balances[accountID] < amount {
		return "", errors.New("cluster rejected: exceeds credits")
	}
	fake.balances[accountID] -= amount
	fake.debits = append(fake.debits, accountCall{ref: ref, accountID: accountID, amount: amount})
	return "dr-" + ref, nil
}

func (fake *fakeAccountLedger) RefundToAccount(_ context.Context, ref, accountID string, amount int64) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.balances[accountID] += amount
	fake.refunds = append(fake.refunds, accountCall{ref: ref, accountID: accountID, amount: amount})
	return "arfnd-" + ref, nil
}

func (fake *fakeAccountLedger) LinkedSettlement(_ context.Context, runID, wallet string, share, platform int64) ([]string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.settlements = append(fake.settlements, settlementCall{runID, wallet, share, platform})
	return []string{"settle-op-" + runID, "settle-pf-" + runID}, nil
}

// --- shared fixtures --------------------------------------------------------

type fareFixture struct {
	pool        *pgxpool.Pool
	store       *PostgresStore
	ticketStore *ticketing.PostgresStore
	tickets     *fakeTicketLedger
	accounts    *fakeAccountLedger
	passes      *PassService
	journeys    *JourneyService
	accountSvc  *AccountService
	settlement  *SettlementService
}

const testSalt = "fare-integration-salt-0123456789abcdef"
const testWebhookSecret = "fare-webhook-hmac-secret-0123456789"

func newFareFixture(t *testing.T) fareFixture {
	t.Helper()
	pool := openPool(t)
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	ticketStore, err := ticketing.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	tickets := &fakeTicketLedger{}
	accounts := newFakeAccountLedger()
	passes, err := NewPassService(store, tickets, accounts, testSalt)
	if err != nil {
		t.Fatal(err)
	}
	journeys, err := NewJourneyService(ticketStore, store, tickets, accounts, testSalt)
	if err != nil {
		t.Fatal(err)
	}
	accountSvc, err := NewAccountService(store, accounts, testSalt, testWebhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	settlement, err := NewSettlementService(store, tickets, accounts)
	if err != nil {
		t.Fatal(err)
	}
	return fareFixture{pool, store, ticketStore, tickets, accounts, passes, journeys, accountSvc, settlement}
}

func (fixture fareFixture) close() { fixture.pool.Close() }

// --- pass purchase saga -----------------------------------------------------

func TestPassPurchaseSagaAndReplay(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	product := PassProduct{
		ProductID: "prod-week-net", Kind: PassKindWeek, ScopeType: ScopeTypeNetwork,
		PriceNGNMinor: 300000, Active: true,
	}
	if err := fixture.passes.CreatePassProduct(ctx, product); err != nil {
		t.Fatal(err)
	}
	request := PassPurchaseRequest{
		ProductID: "prod-week-net", PassengerRef: "commuter-1", Channel: ChannelDirect,
		IdempotencyKey: "pass-purchase-1", CorrelationID: "corr-1", Principal: "passenger:commuter-1",
	}
	pass, err := fixture.passes.Purchase(ctx, request)
	if err != nil {
		t.Fatalf("purchase: %v", err)
	}
	if pass.Status != PassStatusActive || pass.ProductID != product.ProductID {
		t.Fatalf("pass = %+v", pass)
	}
	if !pass.ValidTo.After(pass.ValidFrom) {
		t.Fatal("validity window must be positive")
	}
	// Ledger: exactly one reserve and one post at the product price.
	if len(fixture.tickets.reserves) != 1 || fixture.tickets.reserves[0].amount != 300000 {
		t.Fatalf("reserves = %+v", fixture.tickets.reserves)
	}
	if len(fixture.tickets.posts) != 1 {
		t.Fatalf("posts = %+v", fixture.tickets.posts)
	}
	// Saga states + audit events are durable.
	var state string
	if err := fixture.pool.QueryRow(ctx,
		`SELECT state FROM pass_purchases WHERE idempotency_key = 'pass-purchase-1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != PurchaseIssued {
		t.Fatalf("purchase state = %s", state)
	}
	var events int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ferry_outbox WHERE topic = $1 AND event_type IN ($2, $3, $4)`,
		TopicFare, EventPassReserved, EventPassPaid, EventPassIssued).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 3 {
		t.Fatalf("pass saga outbox events = %d, expected 3", events)
	}
	// Replay of the same idempotency key returns the same pass, no second charge.
	replayed, err := fixture.passes.Purchase(ctx, request)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayed.PassID != pass.PassID {
		t.Fatalf("replay minted a different pass: %s != %s", replayed.PassID, pass.PassID)
	}
	if len(fixture.tickets.reserves) != 1 || len(fixture.tickets.posts) != 1 {
		t.Fatal("replay must not charge again")
	}
	// The same key under a different principal conflicts.
	conflicting := request
	conflicting.Principal = "passenger:mallory"
	if _, err := fixture.passes.Purchase(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got %v", err)
	}
}

// --- fare capping -----------------------------------------------------------

func TestFareCappingExactCapThenZeroFare(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.store.CreateCapRule(ctx, CapRule{
		RuleID: "cap-day-1000", PeriodKind: "DAY", CapMinor: 100000, ScopeType: ScopeTypeNetwork, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedTrip(t, ctx, fixture.pool, "op-cap", "vessel-cap", "trip-cap", "route-cap", 40000, 20)

	charges := make([]int64, 0, 4)
	classes := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		ticket, journey, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
			TripID: "trip-cap", PassengerRef: "cap-commuter", Channel: ChannelDirect,
			IdempotencyKey: fmt.Sprintf("cap-journey-%d", i), CorrelationID: "corr-cap",
			Principal: "passenger:cap-commuter",
		})
		if err != nil {
			t.Fatalf("journey %d: %v", i, err)
		}
		if ticket.State != ticketing.StateIssued {
			t.Fatalf("journey %d ticket state = %s", i, ticket.State)
		}
		charges = append(charges, journey.ChargedMinor)
		classes = append(classes, journey.PricingClass)
	}
	// 400 + 400 + 200 (capped) + 0 (cap covered): exact cap, then zero-fare.
	wantCharges := []int64{40000, 40000, 20000, 0}
	for i := range wantCharges {
		if charges[i] != wantCharges[i] {
			t.Fatalf("charge %d = %d, expected %d (charges %v)", i, charges[i], wantCharges[i], charges)
		}
	}
	if classes[2] != PricingCapped || classes[3] != PricingZeroCap {
		t.Fatalf("pricing classes = %v", classes)
	}
	// Ledger consistency: reserves exactly mirror the charged amounts; the
	// zero-fare journey never touches the ledger.
	if len(fixture.tickets.reserves) != 3 {
		t.Fatalf("reserves = %+v", fixture.tickets.reserves)
	}
	for i, call := range fixture.tickets.reserves {
		if call.amount != wantCharges[i] {
			t.Fatalf("reserve %d amount = %d, expected %d", i, call.amount, wantCharges[i])
		}
	}
	if len(fixture.tickets.posts) != 3 {
		t.Fatalf("posts = %+v", fixture.tickets.posts)
	}
	// Accumulator consistency: spent == sum(charged) == cap.
	var spent int64
	if err := fixture.pool.QueryRow(ctx,
		`SELECT spent_ngn_minor FROM fare_cap_accumulators WHERE period_kind = 'DAY'`).Scan(&spent); err != nil {
		t.Fatal(err)
	}
	if spent != 100000 {
		t.Fatalf("accumulator spent = %d, expected 100000", spent)
	}
	// The zero-fare journey still issued a valid seat ticket (fare 0).
	var fareMinor int64
	var ticketState string
	if err := fixture.pool.QueryRow(ctx,
		`SELECT t.fare_ngn_minor, t.state FROM tickets t
		 JOIN cap_journeys j ON j.ticket_id = t.ticket_id WHERE j.pricing_class = 'ZERO_CAP'`).
		Scan(&fareMinor, &ticketState); err != nil {
		t.Fatal(err)
	}
	if fareMinor != 0 || ticketState != string(ticketing.StateIssued) {
		t.Fatalf("zero-fare ticket = fare %d state %s", fareMinor, ticketState)
	}
}

func TestConcurrentJourneysNeverOverspendCap(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	if err := fixture.store.CreateCapRule(ctx, CapRule{
		RuleID: "cap-conc", PeriodKind: "DAY", CapMinor: 100000, ScopeType: ScopeTypeNetwork, Active: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedTrip(t, ctx, fixture.pool, "op-conc", "vessel-conc", "trip-conc", "route-conc", 30000, 50)

	const buyers = 12
	charged := make([]int64, buyers)
	errs := make([]error, buyers)
	var wait sync.WaitGroup
	for i := 0; i < buyers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, journey, err := fixture.journeys.Purchase(ctx, JourneyPurchaseRequest{
				TripID: "trip-conc", PassengerRef: "conc-commuter", Channel: ChannelDirect,
				IdempotencyKey: fmt.Sprintf("conc-journey-%d", index), CorrelationID: "corr-conc",
				Principal: "passenger:conc-commuter",
			})
			charged[index] = journey.ChargedMinor
			errs[index] = err
		}(i)
	}
	wait.Wait()
	var total int64
	for i := 0; i < buyers; i++ {
		if errs[i] != nil {
			t.Fatalf("buyer %d: %v", i, errs[i])
		}
		total += charged[i]
	}
	if total != 100000 {
		t.Fatalf("total charged = %d, expected exactly the 100000 cap (charges %v)", total, charged)
	}
	var spent int64
	if err := fixture.pool.QueryRow(ctx,
		`SELECT spent_ngn_minor FROM fare_cap_accumulators WHERE period_kind = 'DAY'`).Scan(&spent); err != nil {
		t.Fatal(err)
	}
	if spent != 100000 {
		t.Fatalf("accumulator spent = %d, expected 100000 (never overspent)", spent)
	}
	// Ledger/accumulator consistency: every reserve is either voided (a
	// retried seat-contention attempt) or posted; posted amounts total the cap.
	fixture.tickets.mu.Lock()
	amounts := map[string]int64{}
	for _, call := range fixture.tickets.reserves {
		amounts["rsv-"+call.ref] = call.amount
	}
	voided := map[string]bool{}
	for _, id := range fixture.tickets.voids {
		voided[id] = true
	}
	posted := map[string]bool{}
	var postedTotal int64
	for _, id := range fixture.tickets.posts {
		posted[id] = true
		postedTotal += amounts[id]
	}
	for id := range amounts {
		if !voided[id] && !posted[id] {
			t.Fatalf("reserve %s neither voided nor posted", id)
		}
	}
	fixture.tickets.mu.Unlock()
	if postedTotal != 100000 {
		t.Fatalf("posted ledger total = %d, expected 100000 (accumulator and ledger consistent)", postedTotal)
	}
}

// --- expiry sweep -----------------------------------------------------------

func TestPassExpirySweep(t *testing.T) {
	fixture := newFareFixture(t)
	defer fixture.close()
	ctx := context.Background()

	product := PassProduct{ProductID: "prod-day", Kind: PassKindDay, ScopeType: ScopeTypeNetwork, PriceNGNMinor: 50000, Active: true}
	if err := fixture.passes.CreatePassProduct(ctx, product); err != nil {
		t.Fatal(err)
	}
	pass, err := fixture.passes.Purchase(ctx, PassPurchaseRequest{
		ProductID: "prod-day", PassengerRef: "swept", Channel: ChannelDirect,
		IdempotencyKey: "sweep-purchase", CorrelationID: "corr-sweep", Principal: "passenger:swept",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Age the pass past its validity.
	if _, err := fixture.pool.Exec(ctx,
		`UPDATE passes SET valid_from = $2, valid_to = $3 WHERE pass_id = $1`,
		pass.PassID, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	swept, err := fixture.passes.SweepExpiredPasses(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if swept != 1 {
		t.Fatalf("swept = %d, expected 1", swept)
	}
	reloaded, err := fixture.store.GetPass(ctx, pass.PassID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != PassStatusExpired {
		t.Fatalf("pass status = %s, expected EXPIRED", reloaded.Status)
	}
	var events int
	if err := fixture.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ferry_outbox WHERE event_type = $1 AND subject_id = $2`,
		EventPassExpired, pass.PassID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("expiry events = %d, expected 1", events)
	}
	// Sweep is a no-op on already-expired passes.
	swept, err = fixture.passes.SweepExpiredPasses(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if swept != 0 {
		t.Fatalf("second sweep = %d, expected 0", swept)
	}
}
