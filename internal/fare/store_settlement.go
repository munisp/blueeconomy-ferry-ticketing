package fare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// SettlementAggregate is the usage-attributed revenue of one operator over
// one period (Leicester model: the ledger observes every journey).
type SettlementAggregate struct {
	OperatorID     string `json:"operatorId"`
	PeriodStart    string `json:"periodStart"`
	PeriodEnd      string `json:"periodEnd"`
	Rides          int64  `json:"rides"`
	GrossMinor     int64  `json:"grossNgnMinor"`
	SubsidyMinor   int64  `json:"subsidyNgnMinor"`
	ShareBps       int    `json:"operatorShareBps"`
	OperatorMinor  int64  `json:"operatorShareNgnMinor"`
	PlatformMinor  int64  `json:"platformShareNgnMinor"`
}

// SettlementRule is the revenue-share rule for one operator.
type SettlementRule struct {
	OperatorID      string
	OperatorShareBps int
	Active          bool
}

// UpsertSettlementRule writes one operator's share rule (bps of gross).
func (store *PostgresStore) UpsertSettlementRule(ctx context.Context, rule SettlementRule) error {
	_, err := store.pool.Exec(ctx,
		`INSERT INTO operator_settlement_rules (operator_id, operator_share_bps, active)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (operator_id) DO UPDATE SET operator_share_bps = EXCLUDED.operator_share_bps, active = EXCLUDED.active`,
		rule.OperatorID, rule.OperatorShareBps, rule.Active)
	if err != nil {
		return fmt.Errorf("upsert settlement rule: %w", err)
	}
	return nil
}

// GetSettlementRule loads one operator's share rule.
func (store *PostgresStore) GetSettlementRule(ctx context.Context, operatorID string) (SettlementRule, error) {
	var rule SettlementRule
	err := store.pool.QueryRow(ctx,
		`SELECT operator_id, operator_share_bps, active FROM operator_settlement_rules WHERE operator_id = $1`,
		operatorID).Scan(&rule.OperatorID, &rule.OperatorShareBps, &rule.Active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SettlementRule{}, ErrNotFound
		}
		return SettlementRule{}, fmt.Errorf("load settlement rule: %w", err)
	}
	return rule, nil
}

// AggregateSettlement computes the read-only settlement view: account-based
// journeys (cap_journeys), direct ticket sales outside the cap engine and
// pass rides, attributed per operator over [from, to).
func (store *PostgresStore) AggregateSettlement(ctx context.Context, operatorID string, from, to time.Time, shareBps int) (SettlementAggregate, error) {
	aggregate := SettlementAggregate{
		OperatorID:  operatorID,
		PeriodStart: from.Format("2006-01-02"),
		PeriodEnd:   to.Format("2006-01-02"),
		ShareBps:    shareBps,
	}
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(charged_minor), 0), COALESCE(SUM(standard_fare_minor - charged_minor), 0)
		 FROM cap_journeys
		 WHERE operator_id = $1 AND created_at >= $2 AND created_at < $3 AND NOT reversed`,
		operatorID, from, to).Scan(&aggregate.Rides, &aggregate.GrossMinor, &aggregate.SubsidyMinor); err != nil {
		return aggregate, fmt.Errorf("aggregate capped journeys: %w", err)
	}
	var directRides int64
	var directGross int64
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(SUM(t.fare_ngn_minor), 0)
		 FROM tickets t
		 WHERE t.operator_id = $1 AND t.created_at >= $2 AND t.created_at < $3
		   AND t.channel <> 'ACCOUNT' AND t.state IN ('PAID', 'ISSUED')
		   AND NOT EXISTS (SELECT 1 FROM cap_journeys j WHERE j.ticket_id = t.ticket_id)`,
		operatorID, from, to).Scan(&directRides, &directGross); err != nil {
		return aggregate, fmt.Errorf("aggregate direct tickets: %w", err)
	}
	var passRides int64
	if err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM pass_rides WHERE operator_id = $1 AND admitted_at >= $2 AND admitted_at < $3`,
		operatorID, from, to).Scan(&passRides); err != nil {
		return aggregate, fmt.Errorf("aggregate pass rides: %w", err)
	}
	aggregate.Rides += directRides + passRides
	aggregate.GrossMinor += directGross
	aggregate.OperatorMinor = aggregate.GrossMinor * int64(shareBps) / 10000
	aggregate.PlatformMinor = aggregate.GrossMinor - aggregate.OperatorMinor
	return aggregate, nil
}

// SettlementRun is one executed (ledger-settled) operator split.
type SettlementRun struct {
	RunID          string
	OperatorID     string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	Rides          int64
	GrossMinor     int64
	OperatorMinor  int64
	PlatformMinor  int64
	SubsidyMinor   int64
	LedgerTransfers []string
	CreatedBy      string
	CreatedAt      time.Time
}

// InsertSettlementRun records one executed split with its audit event;
// created is false when the (operator, period) run already exists (a
// settlement is executed exactly once per period).
func (store *PostgresStore) InsertSettlementRun(ctx context.Context, run SettlementRun, event ticketing.Event) (created bool, err error) {
	transferIDs, err := json.Marshal(run.LedgerTransfers)
	if err != nil {
		return false, fmt.Errorf("encode ledger transfer ids: %w", err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin settlement transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`INSERT INTO settlement_runs (run_id, operator_id, period_start, period_end, rides, gross_ngn_minor,
		     operator_share_minor, platform_share_minor, subsidy_minor, ledger_transfer_ids, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (operator_id, period_start, period_end) DO NOTHING`,
		run.RunID, run.OperatorID, run.PeriodStart, run.PeriodEnd, run.Rides, run.GrossMinor,
		run.OperatorMinor, run.PlatformMinor, run.SubsidyMinor, transferIDs, run.CreatedBy)
	if err != nil {
		return false, fmt.Errorf("insert settlement run: %w", err)
	}
	if result.RowsAffected() != 1 {
		return false, nil
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit settlement run: %w", err)
	}
	return true, nil
}

// GetSettlementRun loads one executed run.
func (store *PostgresStore) GetSettlementRun(ctx context.Context, operatorID string, from, to time.Time) (SettlementRun, error) {
	var run SettlementRun
	var transferIDs []byte
	err := store.pool.QueryRow(ctx,
		`SELECT run_id, operator_id, period_start, period_end, rides, gross_ngn_minor, operator_share_minor,
		        platform_share_minor, subsidy_minor, ledger_transfer_ids, created_by, created_at
		 FROM settlement_runs WHERE operator_id = $1 AND period_start = $2 AND period_end = $3`,
		operatorID, from, to).
		Scan(&run.RunID, &run.OperatorID, &run.PeriodStart, &run.PeriodEnd, &run.Rides, &run.GrossMinor,
			&run.OperatorMinor, &run.PlatformMinor, &run.SubsidyMinor, &transferIDs, &run.CreatedBy, &run.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SettlementRun{}, ErrNotFound
		}
		return SettlementRun{}, fmt.Errorf("load settlement run: %w", err)
	}
	if err := json.Unmarshal(transferIDs, &run.LedgerTransfers); err != nil {
		return SettlementRun{}, fmt.Errorf("decode ledger transfer ids: %w", err)
	}
	return run, nil
}

// SubsidyLine is one route's subsidy transparency row (NYC Ferry lesson:
// per-route subsidy is computed and published from day one).
type SubsidyLine struct {
	RouteReference string `json:"routeReference"`
	Rides          int64  `json:"rides"`
	StandardMinor  int64  `json:"standardFareNgnMinor"`
	ChargedMinor   int64  `json:"chargedNgnMinor"`
	SubsidyMinor   int64  `json:"subsidyNgnMinor"`
}

// SubsidyReport aggregates forgone fare (caps, concessions, transfer
// discounts) per route over [from, to).
func (store *PostgresStore) SubsidyReport(ctx context.Context, from, to time.Time) ([]SubsidyLine, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT route_reference, COUNT(*), COALESCE(SUM(standard_fare_minor), 0),
		        COALESCE(SUM(charged_minor), 0), COALESCE(SUM(standard_fare_minor - charged_minor), 0)
		 FROM cap_journeys WHERE created_at >= $1 AND created_at < $2 AND NOT reversed
		 GROUP BY route_reference ORDER BY route_reference`, from, to)
	if err != nil {
		return nil, fmt.Errorf("subsidy report: %w", err)
	}
	defer rows.Close()
	lines := make([]SubsidyLine, 0)
	for rows.Next() {
		var line SubsidyLine
		if err := rows.Scan(&line.RouteReference, &line.Rides, &line.StandardMinor, &line.ChargedMinor, &line.SubsidyMinor); err != nil {
			return nil, fmt.Errorf("scan subsidy line: %w", err)
		}
		lines = append(lines, line)
	}
	return lines, rows.Err()
}

// BestFareAdjustment is one weekly best-fare settlement record.
type BestFareAdjustment struct {
	SubjectRef       string
	PeriodStart      time.Time
	ProductID        string
	SpentMinor       int64
	PassPriceMinor   int64
	AdjustmentMinor  int64
	LedgerTransferID string
}

// BestFareAdjustmentExists reports whether the subject's period was settled.
func (store *PostgresStore) BestFareAdjustmentExists(ctx context.Context, subjectRef string, periodStart time.Time) (bool, error) {
	var exists bool
	if err := store.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM best_fare_adjustments WHERE subject_ref = $1 AND period_start = $2)`,
		subjectRef, periodStart).Scan(&exists); err != nil {
		return false, fmt.Errorf("check best-fare adjustment: %w", err)
	}
	return exists, nil
}

// InsertBestFareAdjustment records one adjustment with its audit event;
// created is false when the subject's period was already settled.
func (store *PostgresStore) InsertBestFareAdjustment(ctx context.Context, adjustment BestFareAdjustment, event ticketing.Event) (created bool, err error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin best-fare transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`INSERT INTO best_fare_adjustments (subject_ref, period_start, product_id, spent_minor, pass_price_minor,
		     adjustment_minor, ledger_transfer_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (subject_ref, period_start) DO NOTHING`,
		adjustment.SubjectRef, adjustment.PeriodStart, adjustment.ProductID, adjustment.SpentMinor,
		adjustment.PassPriceMinor, adjustment.AdjustmentMinor, adjustment.LedgerTransferID)
	if err != nil {
		return false, fmt.Errorf("insert best-fare adjustment: %w", err)
	}
	if result.RowsAffected() != 1 {
		return false, nil
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit best-fare adjustment: %w", err)
	}
	return true, nil
}

// CheapestNetworkWeekPass finds the cheapest active NETWORK WEEK product
// (best-fare guarantee baseline). Scope-aware best-fare (route products) is
// a later refinement; the guarantee is documented as network-scope.
func (store *PostgresStore) CheapestNetworkWeekPass(ctx context.Context) (PassProduct, error) {
	var product PassProduct
	var operatorID *string
	err := store.pool.QueryRow(ctx,
		`SELECT product_id, kind, scope_type, scope_ref, price_ngn_minor, operator_id, active, created_at
		 FROM pass_products WHERE active AND kind = 'WEEK' AND scope_type = 'NETWORK'
		 ORDER BY price_ngn_minor LIMIT 1`).
		Scan(&product.ProductID, &product.Kind, &product.ScopeType, &product.ScopeRef, &product.PriceNGNMinor,
			&operatorID, &product.Active, &product.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PassProduct{}, ErrNotFound
		}
		return PassProduct{}, fmt.Errorf("find cheapest week pass: %w", err)
	}
	if operatorID != nil {
		product.OperatorID = *operatorID
	}
	return product, nil
}
