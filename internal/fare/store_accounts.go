package fare

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// ---------------------------------------------------------------------------
// Fare accounts and instruments
// ---------------------------------------------------------------------------

// OpenFareAccount inserts the account with its audit event in one
// transaction. The ledger account is provisioned by the service first.
func (store *PostgresStore) OpenFareAccount(ctx context.Context, account FareAccount, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin account transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO fare_accounts (account_id, owner_ref, owner_digest, status, concession_class,
		     concession_reference, autoload_enabled, autoload_threshold_minor, autoload_amount_minor,
		     ledger_account_id, cached_balance_minor)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, $10, 0)`,
		account.AccountID, account.OwnerRef, account.OwnerDigest, account.Status, account.ConcessionClass,
		account.ConcessionReference, account.AutoloadEnabled, account.AutoloadThreshold, account.AutoloadAmount,
		account.LedgerAccountID); err != nil {
		return fmt.Errorf("insert fare account: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit account: %w", err)
	}
	return nil
}

// GetFareAccount loads one account.
func (store *PostgresStore) GetFareAccount(ctx context.Context, accountID string) (FareAccount, error) {
	return scanFareAccount(store.pool.QueryRow(ctx,
		`SELECT `+fareAccountColumns+` FROM fare_accounts WHERE account_id = $1`, accountID))
}

const fareAccountColumns = `account_id, owner_ref, owner_digest, status, concession_class, concession_reference,
	autoload_enabled, autoload_threshold_minor, autoload_amount_minor, ledger_account_id,
	cached_balance_minor, balance_as_of, version, created_at, updated_at`

func scanFareAccount(row pgx.Row) (FareAccount, error) {
	var account FareAccount
	var concessionReference *string
	err := row.Scan(&account.AccountID, &account.OwnerRef, &account.OwnerDigest, &account.Status,
		&account.ConcessionClass, &concessionReference, &account.AutoloadEnabled, &account.AutoloadThreshold,
		&account.AutoloadAmount, &account.LedgerAccountID, &account.CachedBalanceMinor, &account.BalanceAsOf,
		&account.Version, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return FareAccount{}, ErrNotFound
		}
		return FareAccount{}, fmt.Errorf("load fare account: %w", err)
	}
	if concessionReference != nil {
		account.ConcessionReference = *concessionReference
	}
	return account, nil
}

// RegisterInstrument inserts one instrument with its audit event.
func (store *PostgresStore) RegisterInstrument(ctx context.Context, instrument Instrument, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin instrument transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO instruments (instrument_id, account_id, kind, token_ref, status)
		 VALUES ($1, $2, $3, $4, $5)`,
		instrument.InstrumentID, instrument.AccountID, instrument.Kind, instrument.TokenRef, instrument.Status); err != nil {
		return fmt.Errorf("insert instrument: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit instrument: %w", err)
	}
	return nil
}

// GetFareAccountByInstrument resolves an ACTIVE instrument token to its account.
func (store *PostgresStore) GetFareAccountByInstrument(ctx context.Context, tokenRef string) (FareAccount, error) {
	return scanFareAccount(store.pool.QueryRow(ctx,
		`SELECT a.account_id, a.owner_ref, a.owner_digest, a.status, a.concession_class, a.concession_reference,
		        a.autoload_enabled, a.autoload_threshold_minor, a.autoload_amount_minor, a.ledger_account_id,
		        a.cached_balance_minor, a.balance_as_of, a.version, a.created_at, a.updated_at
		 FROM fare_accounts a
		 JOIN instruments i ON i.account_id = a.account_id
		 WHERE i.token_ref = $1 AND i.status = 'ACTIVE'`, tokenRef))
}

// AdjustCachedBalance moves the read-model cache (never the money: the
// ledger is authoritative). Used after confirmed journey posts and settled
// offline debits; negative deltas floor at zero and the reconciliation
// report surfaces any drift.
func (store *PostgresStore) AdjustCachedBalance(ctx context.Context, tx pgx.Tx, accountID string, deltaMinor int64) error {
	result, err := tx.Exec(ctx,
		`UPDATE fare_accounts SET cached_balance_minor = GREATEST(0, cached_balance_minor + $2),
		    balance_as_of = now(), version = version + 1, updated_at = now()
		 WHERE account_id = $1`, accountID, deltaMinor)
	if err != nil {
		return fmt.Errorf("adjust cached balance: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("adjust cached balance: %w", ErrNotFound)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Top-ups
// ---------------------------------------------------------------------------

// InsertTopUp persists one top-up (PENDING for rails, CREDITED for agent
// cash) with its event. The idempotency key and reference are unique.
func (store *PostgresStore) InsertTopUp(ctx context.Context, topup TopUp, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin top-up transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO topups (topup_id, account_id, channel, amount_ngn_minor, state, reference,
		     agent_id, idempotency_key, ledger_transfer_id, credited_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, NULLIF($9, ''), $10)`,
		topup.TopUpID, topup.AccountID, topup.Channel, topup.AmountNGNMinor, topup.State, topup.Reference,
		topup.AgentID, topup.IdempotencyKey, topup.LedgerTransferID, topup.CreditedAt); err != nil {
		return fmt.Errorf("insert top-up: %w", err)
	}
	if topup.State == TopUpCredited {
		// Agent cash: the ledger credit already happened; reflect it in the
		// read-model cache in the same transaction.
		if err := store.AdjustCachedBalance(ctx, tx, topup.AccountID, topup.AmountNGNMinor); err != nil {
			return err
		}
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit top-up: %w", err)
	}
	return nil
}

const topupColumns = `topup_id, account_id, channel, amount_ngn_minor, state, reference, external_ref,
	agent_id, idempotency_key, ledger_transfer_id, failure_reason, version, created_at, credited_at`

func scanTopUp(row pgx.Row) (TopUp, error) {
	var topup TopUp
	var externalRef, agentID, ledgerTransferID, failureReason *string
	err := row.Scan(&topup.TopUpID, &topup.AccountID, &topup.Channel, &topup.AmountNGNMinor, &topup.State,
		&topup.Reference, &externalRef, &agentID, &topup.IdempotencyKey, &ledgerTransferID, &failureReason,
		&topup.Version, &topup.CreatedAt, &topup.CreditedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TopUp{}, ErrNotFound
		}
		return TopUp{}, fmt.Errorf("load top-up: %w", err)
	}
	if externalRef != nil {
		topup.ExternalRef = *externalRef
	}
	if agentID != nil {
		topup.AgentID = *agentID
	}
	if ledgerTransferID != nil {
		topup.LedgerTransferID = *ledgerTransferID
	}
	if failureReason != nil {
		topup.FailureReason = *failureReason
	}
	return topup, nil
}

// GetTopUp loads one top-up by id.
func (store *PostgresStore) GetTopUp(ctx context.Context, topupID string) (TopUp, error) {
	return scanTopUp(store.pool.QueryRow(ctx, `SELECT `+topupColumns+` FROM topups WHERE topup_id = $1`, topupID))
}

// GetTopUpByReference resolves one payer-facing reference (webhook input).
func (store *PostgresStore) GetTopUpByReference(ctx context.Context, reference string) (TopUp, error) {
	return scanTopUp(store.pool.QueryRow(ctx, `SELECT `+topupColumns+` FROM topups WHERE reference = $1`, reference))
}

// GetTopUpByIdempotency resolves one idempotency key.
func (store *PostgresStore) GetTopUpByIdempotency(ctx context.Context, key string) (TopUp, error) {
	return scanTopUp(store.pool.QueryRow(ctx, `SELECT `+topupColumns+` FROM topups WHERE idempotency_key = $1`, key))
}

// CreditTopUp settles a PENDING top-up (verified webhook): external_ref
// dedupe, balance cache, audit event — one transaction. credited is false
// when the top-up was already settled (webhook replay).
func (store *PostgresStore) CreditTopUp(ctx context.Context, topup TopUp, externalRef, ledgerTransferID string, event ticketing.Event) (credited bool, err error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin top-up credit transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`UPDATE topups SET state = $2, version = version + 1, external_ref = $3, ledger_transfer_id = $4, credited_at = now()
		 WHERE topup_id = $1 AND state = $5`,
		topup.TopUpID, TopUpCredited, externalRef, ledgerTransferID, TopUpPending)
	if err != nil {
		return false, fmt.Errorf("credit top-up: %w", err)
	}
	if result.RowsAffected() != 1 {
		return false, nil // replay or terminal state: no double credit
	}
	if err := store.AdjustCachedBalance(ctx, tx, topup.AccountID, topup.AmountNGNMinor); err != nil {
		return false, err
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit top-up credit: %w", err)
	}
	return true, nil
}

// FailTopUp marks a PENDING top-up FAILED (verified webhook failure).
func (store *PostgresStore) FailTopUp(ctx context.Context, topupID, externalRef, reason string, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin top-up failure transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`UPDATE topups SET state = $2, version = version + 1, external_ref = NULLIF($3, ''), failure_reason = $4
		 WHERE topup_id = $1 AND state = $5`,
		topupID, TopUpFailed, externalRef, reason, TopUpPending)
	if err != nil {
		return fmt.Errorf("fail top-up: %w", err)
	}
	if result.RowsAffected() != 1 {
		return nil // terminal already; replay
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AccountFlowTotals powers the reconciliation read-model: money in (credited
// top-ups) versus money out (charged account journeys + settled offline
// debits), compared against the cached balance.
type AccountFlowTotals struct {
	CreditedMinor     int64
	RefundedMinor     int64
	JourneyMinor      int64
	OfflineDebitMinor int64
}

// ComputeAccountFlows sums the account's recorded movements.
func (store *PostgresStore) ComputeAccountFlows(ctx context.Context, accountID string) (AccountFlowTotals, error) {
	var totals AccountFlowTotals
	if err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_ngn_minor), 0) FROM topups WHERE account_id = $1 AND state = $2`,
		accountID, TopUpCredited).Scan(&totals.CreditedMinor); err != nil {
		return totals, fmt.Errorf("sum top-ups: %w", err)
	}
	if err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(charged_minor), 0) FROM cap_journeys WHERE account_id = $1 AND NOT reversed`,
		accountID).Scan(&totals.JourneyMinor); err != nil {
		return totals, fmt.Errorf("sum journeys: %w", err)
	}
	if err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_ngn_minor), 0) FROM offline_debits WHERE account_id = $1 AND state = $2`,
		accountID, DebitSettled).Scan(&totals.OfflineDebitMinor); err != nil {
		return totals, fmt.Errorf("sum offline debits: %w", err)
	}
	if err := store.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_minor), 0) FROM fare_account_refunds WHERE account_id = $1 AND state = $2`,
		accountID, RefundSettled).Scan(&totals.RefundedMinor); err != nil {
		return totals, fmt.Errorf("sum account refunds: %w", err)
	}
	return totals, nil
}
