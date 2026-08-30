-- PRA-137: route-scoped best-fare guarantee. Adjustments are recorded per
-- accumulator scope (NETWORK whole-fleet or ROUTE per-route) so the audit
-- trail shows which guarantee paid; the subject/period exactly-once guard
-- stays at the service level (at most ONE best-fare payout per subject per
-- week — the rider receives the single most favorable outcome, never two
-- guarantees over the same money).

ALTER TABLE best_fare_adjustments
    ADD COLUMN IF NOT EXISTS scope_type TEXT NOT NULL DEFAULT 'NETWORK',
    ADD COLUMN IF NOT EXISTS scope_ref  TEXT NOT NULL DEFAULT '';

ALTER TABLE best_fare_adjustments
    DROP CONSTRAINT IF EXISTS best_fare_adjustments_pkey;

ALTER TABLE best_fare_adjustments
    ADD PRIMARY KEY (subject_ref, period_start, scope_type, scope_ref);
