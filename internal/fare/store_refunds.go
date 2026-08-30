package fare

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// store_refunds.go — PRA-136 refund-to-account saga persistence. Every
// transition is version-gated and event-carrying; maker/checker separation
// is enforced in SQL (the UPDATE refuses checker = maker), never just in
// application code.

const accountRefundColumns = `refund_id, account_id, amount_minor, reason, idempotency_key, state,
	maker, checker, ledger_transfer_id, version, correlation_id, created_at, decided_at, settled_at`

// scanAccountRefund scans one refund row.
func scanAccountRefund(row pgx.Row) (AccountRefund, error) {
	var refund AccountRefund
	var checker, transferID *string
	err := row.Scan(&refund.RefundID, &refund.AccountID, &refund.AmountMinor, &refund.Reason,
		&refund.IdempotencyKey, &refund.State, &refund.Maker, &checker, &transferID,
		&refund.Version, &refund.CorrelationID, &refund.CreatedAt, &refund.DecidedAt, &refund.SettledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AccountRefund{}, ErrNotFound
		}
		return AccountRefund{}, fmt.Errorf("scan account refund: %w", err)
	}
	if checker != nil {
		refund.Checker = *checker
	}
	if transferID != nil {
		refund.LedgerTransferID = *transferID
	}
	return refund, nil
}

// InsertAccountRefund persists one REQUESTED refund with its audit event.
func (store *PostgresStore) InsertAccountRefund(ctx context.Context, refund AccountRefund, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin account refund insert: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO fare_account_refunds (refund_id, account_id, amount_minor, reason, idempotency_key,
		     state, maker, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		refund.RefundID, refund.AccountID, refund.AmountMinor, refund.Reason, refund.IdempotencyKey,
		RefundRequested, refund.Maker, refund.CorrelationID); err != nil {
		return fmt.Errorf("insert account refund: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetAccountRefund loads one refund by id.
func (store *PostgresStore) GetAccountRefund(ctx context.Context, refundID string) (AccountRefund, error) {
	return scanAccountRefund(store.pool.QueryRow(ctx,
		`SELECT `+accountRefundColumns+` FROM fare_account_refunds WHERE refund_id = $1`, refundID))
}

// GetAccountRefundByIdempotency resolves one refund by idempotency key.
func (store *PostgresStore) GetAccountRefundByIdempotency(ctx context.Context, key string) (AccountRefund, error) {
	return scanAccountRefund(store.pool.QueryRow(ctx,
		`SELECT `+accountRefundColumns+` FROM fare_account_refunds WHERE idempotency_key = $1`, key))
}

// transitionAccountRefund applies one checker decision with SQL-enforced
// four-eyes: the UPDATE matches only a REQUESTED row whose maker differs
// from the checker. Zero rows means self-approval OR a wrong state; the
// caller disambiguates for the honest error.
func (store *PostgresStore) transitionAccountRefund(ctx context.Context, refundID, fromState, toState, checker string, event ticketing.Event) (AccountRefund, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return AccountRefund{}, fmt.Errorf("begin refund transition: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`UPDATE fare_account_refunds
		 SET state = $3, checker = $4, decided_at = now(), version = version + 1
		 WHERE refund_id = $1 AND state = $2 AND maker <> $4`,
		refundID, fromState, toState, checker)
	if err != nil {
		return AccountRefund{}, fmt.Errorf("transition account refund: %w", err)
	}
	if tag.RowsAffected() == 0 {
		stored, lookupErr := scanAccountRefund(tx.QueryRow(ctx,
			`SELECT `+accountRefundColumns+` FROM fare_account_refunds WHERE refund_id = $1`, refundID))
		if lookupErr != nil {
			return AccountRefund{}, lookupErr
		}
		if stored.Maker == checker {
			return AccountRefund{}, ErrMakerChecker
		}
		return AccountRefund{}, fmt.Errorf("refund %s is %s: %w", refundID, stored.State, ErrInvalidTransition)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return AccountRefund{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AccountRefund{}, fmt.Errorf("commit refund transition: %w", err)
	}
	return store.GetAccountRefund(ctx, refundID)
}

// MarkAccountRefundSettled records the settled state, the deterministic
// ledger transfer id and the cached-balance read-model move in ONE
// transaction with the audit event. Version-gated: a concurrent twin or a
// replayed settle after the first commit touches zero rows (replay-safe).
func (store *PostgresStore) MarkAccountRefundSettled(ctx context.Context, refund AccountRefund, transferID string, event ticketing.Event) (bool, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin refund settle: %w", err)
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`UPDATE fare_account_refunds
		 SET state = $3, ledger_transfer_id = $4, settled_at = $5, version = version + 1
		 WHERE refund_id = $1 AND state = $2 AND version = $6`,
		refund.RefundID, RefundApproved, RefundSettled, transferID, time.Now().UTC(), refund.Version)
	if err != nil {
		return false, fmt.Errorf("mark account refund settled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil // replay or concurrent twin
	}
	if err := store.AdjustCachedBalance(ctx, tx, refund.AccountID, refund.AmountMinor); err != nil {
		return false, err
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit refund settle: %w", err)
	}
	return true, nil
}
