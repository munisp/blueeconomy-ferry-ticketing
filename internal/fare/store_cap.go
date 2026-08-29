package fare

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// PriceInput is one journey pricing request.
type PriceInput struct {
	JourneyID         string
	SubjectRef        string // BlueFare account id, or salted passenger digest
	AccountID         string // "" for non-account journeys
	TripID            string
	RouteReference    string
	OperatorID        string
	StandardFareMinor int64
	ConcessionClass   string
	Now               time.Time
}

// capRuleRow mirrors cap_rules.
type capRuleRow struct {
	RuleID      string
	OperatorID  string
	PeriodKind  string
	CapMinor    int64
	ScopeType   string
	ScopeRef    string
}

// fareRuleRow mirrors fare_rules.
type fareRuleRow struct {
	RuleID          string
	Kind            string
	ConcessionClass string
	RouteGroup      string
	WindowMinutes   int
	DiscountPercent int
}

// DayPeriodStart is the UTC calendar day of t (lazy rollover: derived on
// read/write, never cron-maintained).
func DayPeriodStart(t time.Time) time.Time {
	utc := t.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

// WeekPeriodStart is the ISO Monday of t's week (TfL Monday-Sunday cap).
func WeekPeriodStart(t time.Time) time.Time {
	day := DayPeriodStart(t)
	offset := (int(day.Weekday()) + 6) % 7 // Monday = 0
	return day.AddDate(0, 0, -offset)
}

// PriceJourney atomically (one transaction) applies concession and
// transfer-window rules, reads the capping accumulators under row locks,
// computes charge = min(fare, cap remaining) and records the spend plus the
// decision record and outbox event. Concurrent journeys serialize on the
// accumulator rows, so a cap can never be overspent. Period rollover is
// lazy: period rows are keyed by the derived period start, so a new period
// simply starts a new row.
func (store *PostgresStore) PriceJourney(ctx context.Context, in PriceInput, event ticketing.Event) (CapJourney, error) {
	if in.JourneyID == "" || in.SubjectRef == "" || in.TripID == "" || in.StandardFareMinor < 0 {
		return CapJourney{}, errors.New("journey id, subject, trip and non-negative fare are required")
	}
	journey := CapJourney{
		JourneyID:         in.JourneyID,
		SubjectRef:        in.SubjectRef,
		AccountID:         in.AccountID,
		TripID:            in.TripID,
		RouteReference:    in.RouteReference,
		OperatorID:        in.OperatorID,
		StandardFareMinor: in.StandardFareMinor,
		ConcessionClass:   in.ConcessionClass,
		PricingClass:      PricingStandard,
		CreatedAt:         in.Now,
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return CapJourney{}, fmt.Errorf("begin pricing transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Encoded fare rules (operator-specific or platform default).
	rules, err := store.activeFareRulesTx(ctx, tx, in.OperatorID)
	if err != nil {
		return CapJourney{}, err
	}
	fare := in.StandardFareMinor
	if in.ConcessionClass != "" && in.ConcessionClass != ConcessionStandard {
		for _, rule := range rules {
			if rule.Kind == "CONCESSION" && rule.ConcessionClass == in.ConcessionClass {
				fare = discount(in.StandardFareMinor, rule.DiscountPercent)
				journey.PricingClass = PricingConcession
				break
			}
		}
	}
	// Transfer-window discount: a second leg on a different route inside the
	// same route group within the window prices at the rule discount.
	transferFare, transferOK, err := store.transferFareTx(ctx, tx, rules, in)
	if err != nil {
		return CapJourney{}, err
	}
	if transferOK && transferFare < fare {
		fare = transferFare
		journey.PricingClass = PricingTransfer
	}

	// Capping: every matching rule accumulates independently; the charge is
	// bounded by the tightest remaining allowance.
	capRules, err := store.matchingCapRulesTx(ctx, tx, in.OperatorID, in.RouteReference)
	if err != nil {
		return CapJourney{}, err
	}
	type lockedAccumulator struct {
		periodKind string
		periodStart time.Time
		scopeType   string
		scopeRef    string
		remaining   int64
	}
	locked := make([]lockedAccumulator, 0, len(capRules))
	charge := fare
	capBinding := false
	for _, rule := range capRules {
		periodStart := DayPeriodStart(in.Now)
		if rule.PeriodKind == "WEEK" {
			periodStart = WeekPeriodStart(in.Now)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO fare_cap_accumulators (subject_ref, period_kind, period_start, scope_type, scope_ref)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			in.SubjectRef, rule.PeriodKind, periodStart, rule.ScopeType, rule.ScopeRef); err != nil {
			return CapJourney{}, fmt.Errorf("upsert cap accumulator: %w", err)
		}
		var spent int64
		if err := tx.QueryRow(ctx,
			`SELECT spent_ngn_minor FROM fare_cap_accumulators
			 WHERE subject_ref = $1 AND period_kind = $2 AND period_start = $3 AND scope_type = $4 AND scope_ref = $5
			 FOR UPDATE`,
			in.SubjectRef, rule.PeriodKind, periodStart, rule.ScopeType, rule.ScopeRef).Scan(&spent); err != nil {
			return CapJourney{}, fmt.Errorf("lock cap accumulator: %w", err)
		}
		remaining := rule.CapMinor - spent
		if remaining < 0 {
			remaining = 0
		}
		locked = append(locked, lockedAccumulator{rule.PeriodKind, periodStart, rule.ScopeType, rule.ScopeRef, remaining})
		if remaining < charge {
			charge = remaining
			capBinding = true
		}
	}
	if capBinding {
		if charge == 0 {
			journey.PricingClass = PricingZeroCap
		} else {
			journey.PricingClass = PricingCapped
		}
	}
	for _, acc := range locked {
		if _, err := tx.Exec(ctx,
			`UPDATE fare_cap_accumulators SET spent_ngn_minor = spent_ngn_minor + $6, updated_at = now()
			 WHERE subject_ref = $1 AND period_kind = $2 AND period_start = $3 AND scope_type = $4 AND scope_ref = $5`,
			in.SubjectRef, acc.periodKind, acc.periodStart, acc.scopeType, acc.scopeRef, charge); err != nil {
			return CapJourney{}, fmt.Errorf("record cap spend: %w", err)
		}
	}
	journey.ChargedMinor = charge
	if _, err := tx.Exec(ctx,
		`INSERT INTO cap_journeys (journey_id, subject_ref, account_id, trip_id, route_reference, operator_id,
		     standard_fare_minor, charged_minor, pricing_class, concession_class)
		 VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10)`,
		journey.JourneyID, journey.SubjectRef, journey.AccountID, journey.TripID, journey.RouteReference,
		journey.OperatorID, journey.StandardFareMinor, journey.ChargedMinor, journey.PricingClass,
		journey.ConcessionClass); err != nil {
		return CapJourney{}, fmt.Errorf("record cap journey: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return CapJourney{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CapJourney{}, fmt.Errorf("commit pricing: %w", err)
	}
	return journey, nil
}

// discount applies a percentage discount, rounding down (passenger-favourable).
func discount(amountMinor int64, percent int) int64 {
	return amountMinor * int64(100-percent) / 100
}

func (store *PostgresStore) activeFareRulesTx(ctx context.Context, tx pgx.Tx, operatorID string) ([]fareRuleRow, error) {
	rows, err := tx.Query(ctx,
		`SELECT rule_id, kind, concession_class, route_group, window_minutes, discount_percent
		 FROM fare_rules WHERE active AND (operator_id IS NULL OR operator_id = $1)`, operatorID)
	if err != nil {
		return nil, fmt.Errorf("list fare rules: %w", err)
	}
	defer rows.Close()
	rules := make([]fareRuleRow, 0)
	for rows.Next() {
		var rule fareRuleRow
		var concessionClass, routeGroup *string
		var windowMinutes *int
		if err := rows.Scan(&rule.RuleID, &rule.Kind, &concessionClass, &routeGroup, &windowMinutes, &rule.DiscountPercent); err != nil {
			return nil, fmt.Errorf("scan fare rule: %w", err)
		}
		if concessionClass != nil {
			rule.ConcessionClass = *concessionClass
		}
		if routeGroup != nil {
			rule.RouteGroup = *routeGroup
		}
		if windowMinutes != nil {
			rule.WindowMinutes = *windowMinutes
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// transferFareTx evaluates TRANSFER_WINDOW rules: the passenger's most
// recent non-reversed journey on a different route inside the same route
// group, boarded within the window, discounts this leg.
func (store *PostgresStore) transferFareTx(ctx context.Context, tx pgx.Tx, rules []fareRuleRow, in PriceInput) (int64, bool, error) {
	best := int64(-1)
	for _, rule := range rules {
		if rule.Kind != "TRANSFER_WINDOW" || rule.RouteGroup == "" || rule.WindowMinutes <= 0 {
			continue
		}
		var inGroup bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM route_groups WHERE route_reference = $1 AND group_name = $2)`,
			in.RouteReference, rule.RouteGroup).Scan(&inGroup); err != nil {
			return 0, false, fmt.Errorf("check route group: %w", err)
		}
		if !inGroup {
			continue
		}
		since := in.Now.Add(-time.Duration(rule.WindowMinutes) * time.Minute)
		var lastRoute string
		err := tx.QueryRow(ctx,
			`SELECT route_reference FROM cap_journeys
			 WHERE subject_ref = $1 AND route_reference <> $2 AND created_at >= $3 AND NOT reversed
			 ORDER BY created_at DESC LIMIT 1`,
			in.SubjectRef, in.RouteReference, since).Scan(&lastRoute)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return 0, false, fmt.Errorf("find prior transfer leg: %w", err)
		}
		var lastInGroup bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM route_groups WHERE route_reference = $1 AND group_name = $2)`,
			lastRoute, rule.RouteGroup).Scan(&lastInGroup); err != nil {
			return 0, false, fmt.Errorf("check prior leg route group: %w", err)
		}
		if !lastInGroup {
			continue
		}
		candidate := discount(in.StandardFareMinor, rule.DiscountPercent)
		if best < 0 || candidate < best {
			best = candidate
		}
	}
	if best < 0 {
		return 0, false, nil
	}
	return best, true, nil
}

// matchingCapRulesTx resolves the active cap rules applying to this journey:
// NETWORK rules, ROUTE rules matching the route, and ZONE rules matching the
// route's zone. Operator-specific and platform rules both apply.
func (store *PostgresStore) matchingCapRulesTx(ctx context.Context, tx pgx.Tx, operatorID, routeReference string) ([]capRuleRow, error) {
	rows, err := tx.Query(ctx,
		`SELECT rule_id, operator_id, period_kind, cap_ngn_minor, scope_type, scope_ref FROM cap_rules
		 WHERE active AND (operator_id IS NULL OR operator_id = $1)
		   AND (scope_type = 'NETWORK'
		        OR (scope_type = 'ROUTE' AND scope_ref = $2)
		        OR (scope_type = 'ZONE' AND scope_ref = (SELECT zone FROM route_zones WHERE route_reference = $2)))`,
		operatorID, routeReference)
	if err != nil {
		return nil, fmt.Errorf("list matching cap rules: %w", err)
	}
	defer rows.Close()
	rules := make([]capRuleRow, 0)
	for rows.Next() {
		var rule capRuleRow
		var operator *string
		if err := rows.Scan(&rule.RuleID, &operator, &rule.PeriodKind, &rule.CapMinor, &rule.ScopeType, &rule.ScopeRef); err != nil {
			return nil, fmt.Errorf("scan cap rule: %w", err)
		}
		if operator != nil {
			rule.OperatorID = *operator
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ReverseJourney compensates a priced journey whose purchase failed: the
// spend is returned to every affected accumulator and the journey is marked
// reversed, atomically with the audit event. Replay-safe (a reversed journey
// reverses no further).
func (store *PostgresStore) ReverseJourney(ctx context.Context, journeyID string, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin reversal transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var journey CapJourney
	err = tx.QueryRow(ctx,
		`SELECT journey_id, subject_ref, charged_minor, reversed, created_at FROM cap_journeys
		 WHERE journey_id = $1 FOR UPDATE`, journeyID).
		Scan(&journey.JourneyID, &journey.SubjectRef, &journey.ChargedMinor, &journey.Reversed, &journey.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lock cap journey: %w", err)
	}
	if journey.Reversed {
		return nil // idempotent: already compensated
	}
	for _, periodKind := range []string{"DAY", "WEEK"} {
		periodStart := DayPeriodStart(journey.CreatedAt)
		if periodKind == "WEEK" {
			periodStart = WeekPeriodStart(journey.CreatedAt)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE fare_cap_accumulators SET spent_ngn_minor = GREATEST(0, spent_ngn_minor - $4), updated_at = now()
			 WHERE subject_ref = $1 AND period_kind = $2 AND period_start = $3`,
			journey.SubjectRef, periodKind, periodStart, journey.ChargedMinor); err != nil {
			return fmt.Errorf("return cap spend: %w", err)
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE cap_journeys SET reversed = TRUE WHERE journey_id = $1`, journeyID); err != nil {
		return fmt.Errorf("mark journey reversed: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AttachTicket links the issued ticket to its pricing decision (called when
// the purchase saga completes; informational, money consistency never
// depends on it).
func (store *PostgresStore) AttachTicket(ctx context.Context, journeyID, ticketID string) error {
	if _, err := store.pool.Exec(ctx,
		`UPDATE cap_journeys SET ticket_id = $2 WHERE journey_id = $1`, journeyID, ticketID); err != nil {
		return fmt.Errorf("attach ticket to journey: %w", err)
	}
	return nil
}

// GetCapJourney loads one pricing decision.
func (store *PostgresStore) GetCapJourney(ctx context.Context, journeyID string) (CapJourney, error) {
	var journey CapJourney
	var accountID, ticketID *string
	err := store.pool.QueryRow(ctx,
		`SELECT journey_id, subject_ref, account_id, trip_id, route_reference, operator_id,
		        standard_fare_minor, charged_minor, pricing_class, concession_class, ticket_id, reversed, created_at
		 FROM cap_journeys WHERE journey_id = $1`, journeyID).
		Scan(&journey.JourneyID, &journey.SubjectRef, &accountID, &journey.TripID, &journey.RouteReference,
			&journey.OperatorID, &journey.StandardFareMinor, &journey.ChargedMinor, &journey.PricingClass,
			&journey.ConcessionClass, &ticketID, &journey.Reversed, &journey.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CapJourney{}, ErrNotFound
		}
		return CapJourney{}, fmt.Errorf("load cap journey: %w", err)
	}
	if accountID != nil {
		journey.AccountID = *accountID
	}
	if ticketID != nil {
		journey.TicketID = *ticketID
	}
	return journey, nil
}

// Accumulator is one fare_cap_accumulators row (report/best-fare input).
type Accumulator struct {
	SubjectRef    string
	PeriodKind    string
	PeriodStart   time.Time
	ScopeType     string
	ScopeRef      string
	SpentMinor    int64
}

// ListAccumulators returns every accumulator for one period.
func (store *PostgresStore) ListAccumulators(ctx context.Context, periodKind string, periodStart time.Time) ([]Accumulator, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT subject_ref, period_kind, period_start, scope_type, scope_ref, spent_ngn_minor
		 FROM fare_cap_accumulators WHERE period_kind = $1 AND period_start = $2`, periodKind, periodStart)
	if err != nil {
		return nil, fmt.Errorf("list accumulators: %w", err)
	}
	defer rows.Close()
	accumulators := make([]Accumulator, 0)
	for rows.Next() {
		var acc Accumulator
		if err := rows.Scan(&acc.SubjectRef, &acc.PeriodKind, &acc.PeriodStart, &acc.ScopeType, &acc.ScopeRef, &acc.SpentMinor); err != nil {
			return nil, fmt.Errorf("scan accumulator: %w", err)
		}
		accumulators = append(accumulators, acc)
	}
	return accumulators, rows.Err()
}
