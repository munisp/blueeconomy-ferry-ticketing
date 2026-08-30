package fare

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// SettlementService runs operator revenue-share splits as atomic ledger
// linked chains and serves the read-only reports (settlement, subsidy,
// best-fare). Usage attribution is ledger-native (Leicester model): every
// journey flows through this service's decision records.
type SettlementService struct {
	store    *PostgresStore
	tickets  ticketing.Ledger
	accounts AccountLedger
	now      func() time.Time
}

// NewSettlementService fails closed on any missing dependency.
func NewSettlementService(store *PostgresStore, tickets ticketing.Ledger, accounts AccountLedger) (*SettlementService, error) {
	if store == nil {
		return nil, errors.New("fare store is required")
	}
	if tickets == nil || accounts == nil {
		return nil, errors.New("ledgers are required (fail-closed)")
	}
	return &SettlementService{store: store, tickets: tickets, accounts: accounts,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// Report computes the read-only settlement view for one operator and period.
func (service *SettlementService) Report(ctx context.Context, operatorID string, from, to time.Time) (SettlementAggregate, error) {
	if operatorID == "" || !from.Before(to) {
		return SettlementAggregate{}, errors.New("operator id and a valid period are required")
	}
	rule, err := service.store.GetSettlementRule(ctx, operatorID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SettlementAggregate{}, fmt.Errorf("operator %s has no settlement rule: %w", operatorID, ErrNotFound)
		}
		return SettlementAggregate{}, err
	}
	return service.store.AggregateSettlement(ctx, operatorID, from, to, rule.OperatorShareBps)
}

// Run executes one operator split: the linked transfer chain moves the
// operator share to the operator wallet and the remainder to the platform
// fee account, all-or-nothing. A period settles exactly once (replay returns
// the recorded run).
func (service *SettlementService) Run(ctx context.Context, operatorID string, from, to time.Time, principal, correlationID string) (SettlementRun, error) {
	if principal == "" {
		return SettlementRun{}, errors.New("settlement principal is required")
	}
	if existing, err := service.store.GetSettlementRun(ctx, operatorID, from, to); err == nil {
		return existing, nil // exactly-once per period
	} else if !errors.Is(err, ErrNotFound) {
		return SettlementRun{}, err
	}
	aggregate, err := service.Report(ctx, operatorID, from, to)
	if err != nil {
		return SettlementRun{}, err
	}
	if aggregate.GrossMinor <= 0 {
		return SettlementRun{}, errors.New("settlement period has no revenue to split")
	}
	runID := uuid.NewString()
	wallet := ledger.OperatorWalletID(operatorID)
	if err := service.accounts.EnsureAccount(wallet, true); err != nil {
		return SettlementRun{}, fmt.Errorf("provision operator wallet: %w", err)
	}
	transferIDs, err := service.accounts.LinkedSettlement(ctx, runID, wallet.String(), aggregate.OperatorMinor, aggregate.PlatformMinor)
	if err != nil {
		return SettlementRun{}, fmt.Errorf("execute linked settlement: %w", err)
	}
	run := SettlementRun{
		RunID:           runID,
		OperatorID:      operatorID,
		PeriodStart:     from,
		PeriodEnd:       to,
		Rides:           aggregate.Rides,
		GrossMinor:      aggregate.GrossMinor,
		OperatorMinor:   aggregate.OperatorMinor,
		PlatformMinor:   aggregate.PlatformMinor,
		SubsidyMinor:    aggregate.SubsidyMinor,
		LedgerTransfers: transferIDs,
		CreatedBy:       principal,
	}
	created, err := service.store.InsertSettlementRun(ctx, run, ticketing.Event{
		EventID:       uuid.NewString(),
		Topic:         TopicFare,
		SubjectID:     runID,
		EventType:     EventSettlementRunCompleted,
		CorrelationID: correlationOrNew(correlationID),
		Payload: map[string]any{
			"run_id":                runID,
			"operator_id":           operatorID,
			"period_start":          from.Format("2006-01-02"),
			"period_end":            to.Format("2006-01-02"),
			"rides":                 aggregate.Rides,
			"gross_ngn_minor":       aggregate.GrossMinor,
			"operator_share_minor":  aggregate.OperatorMinor,
			"platform_share_minor":  aggregate.PlatformMinor,
			"subsidy_ngn_minor":     aggregate.SubsidyMinor,
			"ledger_transfer_ids":   transferIDs,
			"principal_id":          principal,
		},
	})
	if err != nil {
		return SettlementRun{}, err
	}
	if !created {
		// Concurrent twin settled first; the recorded run is authoritative.
		return service.store.GetSettlementRun(ctx, operatorID, from, to)
	}
	return run, nil
}

// Subsidy serves the per-route subsidy transparency report.
func (service *SettlementService) Subsidy(ctx context.Context, from, to time.Time) ([]SubsidyLine, error) {
	if !from.Before(to) {
		return nil, errors.New("a valid period is required")
	}
	return service.store.SubsidyReport(ctx, from, to)
}

// SettleBestFare implements the best-fare guarantee for one ISO week
// (PRA-137, scope-aware): every WEEK accumulator scope with a matching WEEK
// pass product yields a candidate guarantee — NETWORK spend vs the cheapest
// NETWORK pass, ROUTE spend vs the cheapest WEEK pass scoped to that route.
// The subject receives the single MOST FAVORABLE candidate (max adjustment)
// — best-fare is one guarantee, never two payouts over the same money.
// Exactly-once per subject per period (service guard + scope-keyed PK +
// deterministic transfer ID). Callable as a period-settlement job after the
// week closes; lazy per-subject evaluation reuses the same path.
func (service *SettlementService) SettleBestFare(ctx context.Context, weekStart time.Time, correlationID string) (int, error) {
	periodStart := WeekPeriodStart(weekStart)
	accumulators, err := service.store.ListAccumulators(ctx, "WEEK", periodStart)
	if err != nil {
		return 0, err
	}
	// bestCandidate[subject] = the scope guarantee that pays the most.
	type candidate struct {
		accumulator Accumulator
		product     PassProduct
		adjustment  int64
	}
	best := map[string]candidate{}
	for _, accumulator := range accumulators {
		if accumulator.ScopeType != ScopeTypeNetwork && accumulator.ScopeType != ScopeTypeRoute {
			continue
		}
		product, err := service.store.CheapestWeekPassForScope(ctx, accumulator.ScopeType, accumulator.ScopeRef)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // no WEEK product covers this scope: no guarantee
			}
			return 0, err
		}
		adjustment := accumulator.SpentMinor - product.PriceNGNMinor
		if adjustment <= 0 {
			continue
		}
		if current, ok := best[accumulator.SubjectRef]; !ok || adjustment > current.adjustment {
			best[accumulator.SubjectRef] = candidate{accumulator, product, adjustment}
		}
	}
	settled := 0
	for _, winner := range best {
		// Serialize per subject: guard lock + exists-check, then credit, then
		// record — one critical section (the deterministic transfer ID is the
		// cluster-side backstop, not the mechanism).
		guard, exists, err := service.store.BeginBestFareGuard(ctx, winner.accumulator.SubjectRef, periodStart)
		if err != nil {
			return settled, err
		}
		if exists {
			guard.Rollback(ctx)
			continue
		}
		reference := fmt.Sprintf("bestfare:%s:%s:%s:%s", winner.accumulator.SubjectRef,
			periodStart.Format("2006-01-02"), winner.accumulator.ScopeType, winner.accumulator.ScopeRef)
		transferID, err := service.creditBestFare(ctx, guard, winner.accumulator.SubjectRef, reference, winner.adjustment)
		if err != nil {
			guard.Rollback(ctx)
			return settled, fmt.Errorf("settle best fare for %s: %w", winner.accumulator.SubjectRef, err)
		}
		product := winner.product
		accumulator := winner.accumulator
		adjustment := winner.adjustment
		created, err := service.store.InsertBestFareAdjustmentTx(ctx, guard, BestFareAdjustment{
			SubjectRef:       accumulator.SubjectRef,
			PeriodStart:      periodStart,
			ScopeType:        accumulator.ScopeType,
			ScopeRef:         accumulator.ScopeRef,
			ProductID:        product.ProductID,
			SpentMinor:       accumulator.SpentMinor,
			PassPriceMinor:   product.PriceNGNMinor,
			AdjustmentMinor:  adjustment,
			LedgerTransferID: transferID,
		}, ticketing.Event{
			EventID:       uuid.NewString(),
			Topic:         TopicFare,
			SubjectID:     accumulator.SubjectRef,
			EventType:     EventBestFareAdjusted,
			CorrelationID: correlationOrNew(correlationID),
			Payload: map[string]any{
				"subject_ref":          accumulator.SubjectRef,
				"period_start":         periodStart.Format("2006-01-02"),
				"product_id":           product.ProductID,
				"spent_ngn_minor":      accumulator.SpentMinor,
				"pass_price_ngn_minor": product.PriceNGNMinor,
				"adjustment_ngn_minor": adjustment,
				"ledger_transfer_id":   transferID,
			},
		})
		if err != nil {
			return settled, err
		}
		if created {
			settled++
		}
	}
	return settled, nil
}

// creditBestFare moves the adjustment inside the guard transaction: account
// subjects are refunded to their fare account (read-model cache follows in
// the same tx); ticket-only subjects are refunded to passenger clearing.
// All PG work rides the guard tx — never a second pool connection while the
// advisory lock is held.
func (service *SettlementService) creditBestFare(ctx context.Context, tx pgx.Tx, subjectRef, reference string, adjustment int64) (string, error) {
	account, err := service.store.GetFareAccountTx(ctx, tx, subjectRef)
	if err == nil {
		transferID, err := service.accounts.RefundToAccount(ctx, reference, account.LedgerAccountID, adjustment)
		if err != nil {
			return "", err
		}
		if err := service.store.AdjustCachedBalance(ctx, tx, subjectRef, adjustment); err != nil {
			return "", err
		}
		return transferID, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	// Ticket-only subject (digest-keyed): refund the difference from operator
	// revenue to passenger clearing, the same money path as a ticket refund,
	// keyed by the deterministic best-fare reference.
	return service.tickets.Refund(ctx, reference, adjustment)
}
