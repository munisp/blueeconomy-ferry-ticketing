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
// application code. Decision + settlement run inside ONE advisory-locked
// transaction per refund so concurrent checkers serialize: the ledger leg
// executes at most once (the deterministic transfer ID is the backstop,
// not the mechanism).

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

// BeginAccountRefundGuard opens the per-refund critical section: a
// transaction holding the refund's advisory lock with the row re-read
// inside. All decision/settlement PG work must ride this transaction — no
// second pool connection while the lock is held.
func (store *PostgresStore) BeginAccountRefundGuard(ctx context.Context, refundID string) (pgx.Tx, AccountRefund, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, AccountRefund{}, fmt.Errorf("begin refund guard: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "refund:"+refundID); err != nil {
		tx.Rollback(ctx)
		return nil, AccountRefund{}, fmt.Errorf("lock refund: %w", err)
	}
	refund, err := scanAccountRefund(tx.QueryRow(ctx,
		`SELECT `+accountRefundColumns+` FROM fare_account_refunds WHERE refund_id = $1`, refundID))
	if err != nil {
		tx.Rollback(ctx)
		return nil, AccountRefund{}, err
	}
	return tx, refund, nil
}

// TransitionAccountRefundTx applies one checker decision inside the guard
// transaction with SQL-enforced four-eyes. Zero rows means self-approval OR
// a wrong state; the error names which.
func (store *PostgresStore) TransitionAccountRefundTx(ctx context.Context, tx pgx.Tx, refund AccountRefund, toState, checker string, event ticketing.Event) (AccountRefund, error) {
	tag, err := tx.Exec(ctx,
		`UPDATE fare_account_refunds
		 SET state = $3, checker = $4, decided_at = now(), version = version + 1
		 WHERE refund_id = $1 AND state = $2 AND maker <> $4`,
		refund.RefundID, refund.State, toState, checker)
	if err != nil {
		return AccountRefund{}, fmt.Errorf("transition account refund: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if refund.Maker == checker {
			return AccountRefund{}, ErrMakerChecker
		}
		return AccountRefund{}, fmt.Errorf("refund %s is %s: %w", refund.RefundID, refund.State, ErrInvalidTransition)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return AccountRefund{}, err
	}
	refund.State = toState
	refund.Checker = checker
	refund.Version++
	return refund, nil
}

// MarkAccountRefundSettledTx records settlement inside the guard
// transaction (ledger transfer id + cached-balance read-model + audit
// event). Version-gated: a crash-recovered settle retry after the first
// commit touches zero rows (replay-safe).
func (store *PostgresStore) MarkAccountRefundSettledTx(ctx context.Context, tx pgx.Tx, refund AccountRefund, transferID string, event ticketing.Event) (bool, error) {
	tag, err := tx.Exec(ctx,
		`UPDATE fare_account_refunds
		 SET state = $3, ledger_transfer_id = $4, settled_at = $5, version = version + 1
		 WHERE refund_id = $1 AND state = $2 AND version = $6`,
		refund.RefundID, RefundApproved, RefundSettled, transferID, time.Now().UTC(), refund.Version)
	if err != nil {
		return false, fmt.Errorf("mark account refund settled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil // replay after a crash between ledger and record
	}
	if err := store.AdjustCachedBalance(ctx, tx, refund.AccountID, refund.AmountMinor); err != nil {
		return false, err
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	return true, nil
}
