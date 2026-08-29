package fare

import (
	"context"
	"fmt"
)

// CapRule is one configurable fare cap (per operator or platform default).
type CapRule struct {
	RuleID     string
	OperatorID string
	PeriodKind string
	CapMinor   int64
	ScopeType  string
	ScopeRef   string
	Active     bool
}

// CreateCapRule registers one cap rule.
func (store *PostgresStore) CreateCapRule(ctx context.Context, rule CapRule) error {
	if rule.RuleID == "" || rule.CapMinor <= 0 {
		return errInvalidRule("rule id and positive cap are required")
	}
	if rule.PeriodKind != "DAY" && rule.PeriodKind != "WEEK" {
		return errInvalidRule("period kind must be DAY or WEEK")
	}
	switch rule.ScopeType {
	case ScopeTypeNetwork:
		rule.ScopeRef = ""
	case ScopeTypeRoute, ScopeTypeZone:
		if rule.ScopeRef == "" {
			return errInvalidRule("ROUTE and ZONE rules require a scope reference")
		}
	default:
		return errInvalidRule("scope type must be NETWORK, ZONE or ROUTE")
	}
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO cap_rules (rule_id, operator_id, period_kind, cap_ngn_minor, scope_type, scope_ref, active)
		 VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7)`,
		rule.RuleID, rule.OperatorID, rule.PeriodKind, rule.CapMinor, rule.ScopeType, rule.ScopeRef, rule.Active); err != nil {
		return fmt.Errorf("insert cap rule: %w", err)
	}
	return nil
}

// FareRule is one encoded concession or transfer-window rule.
type FareRule struct {
	RuleID               string
	Kind                 string
	OperatorID           string
	ConcessionClass      string
	RouteGroup           string
	WindowMinutes        int
	DiscountPercent      int
	EligibilityReference string
	Active               bool
}

// CreateFareRule registers one fare rule. Concession rules require an
// eligibility reference (encoded policy, never discretion); transfer rules
// require a route group and a positive window.
func (store *PostgresStore) CreateFareRule(ctx context.Context, rule FareRule) error {
	if rule.RuleID == "" || rule.DiscountPercent < 0 || rule.DiscountPercent > 100 {
		return errInvalidRule("rule id and a discount within 0..100 are required")
	}
	var concessionClass, routeGroup *string
	var windowMinutes *int
	switch rule.Kind {
	case "CONCESSION":
		switch rule.ConcessionClass {
		case ConcessionStudent, ConcessionElderly, ConcessionPWD:
		default:
			return errInvalidRule("concession class must be STUDENT, ELDERLY or PWD")
		}
		if rule.EligibilityReference == "" {
			return errInvalidRule("concession rules require an eligibility reference")
		}
		concessionClass = &rule.ConcessionClass
	case "TRANSFER_WINDOW":
		if rule.RouteGroup == "" || rule.WindowMinutes <= 0 {
			return errInvalidRule("transfer rules require a route group and a positive window")
		}
		routeGroup = &rule.RouteGroup
		windowMinutes = &rule.WindowMinutes
	default:
		return errInvalidRule("rule kind must be CONCESSION or TRANSFER_WINDOW")
	}
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO fare_rules (rule_id, kind, operator_id, concession_class, route_group, window_minutes,
		     discount_percent, eligibility_reference, active)
		 VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, NULLIF($8, ''), $9)`,
		rule.RuleID, rule.Kind, rule.OperatorID, concessionClass, routeGroup, windowMinutes,
		rule.DiscountPercent, rule.EligibilityReference, rule.Active); err != nil {
		return fmt.Errorf("insert fare rule: %w", err)
	}
	return nil
}

// SetRouteZone maps a route to its zone (zone-scoped caps).
func (store *PostgresStore) SetRouteZone(ctx context.Context, routeReference, zone string) error {
	if routeReference == "" || zone == "" {
		return errInvalidRule("route reference and zone are required")
	}
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO route_zones (route_reference, zone) VALUES ($1, $2)
		 ON CONFLICT (route_reference) DO UPDATE SET zone = EXCLUDED.zone`, routeReference, zone); err != nil {
		return fmt.Errorf("set route zone: %w", err)
	}
	return nil
}

// AddRouteGroupMember maps a route into a transfer group.
func (store *PostgresStore) AddRouteGroupMember(ctx context.Context, routeReference, groupName string) error {
	if routeReference == "" || groupName == "" {
		return errInvalidRule("route reference and group name are required")
	}
	if _, err := store.pool.Exec(ctx,
		`INSERT INTO route_groups (route_reference, group_name) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		routeReference, groupName); err != nil {
		return fmt.Errorf("add route group member: %w", err)
	}
	return nil
}

// GetPassOwnerPrincipal resolves the purchasing principal of one pass
// (ownership checks at the API edge).
func (store *PostgresStore) GetPassOwnerPrincipal(ctx context.Context, passID string) (string, error) {
	var principal string
	err := store.pool.QueryRow(ctx,
		`SELECT p.purchaser_principal FROM pass_purchases p
		 JOIN passes s ON s.purchase_id = p.purchase_id WHERE s.pass_id = $1`, passID).Scan(&principal)
	if err != nil {
		return "", ErrNotFound
	}
	return principal, nil
}

type invalidRuleError string

func (err invalidRuleError) Error() string { return string(err) }

func errInvalidRule(message string) error { return invalidRuleError(message) }
