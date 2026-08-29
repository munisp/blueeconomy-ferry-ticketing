package fare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// PostgresStore is the production fare persistence boundary. Every mutating
// method writes its outbox events in the same transaction as the domain
// change, mirroring the ticketing store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore fails closed on a nil pool.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	return &PostgresStore{pool: pool}, nil
}

// Pool exposes the underlying pool for composed services (read-only queries).
func (store *PostgresStore) Pool() *pgxpool.Pool { return store.pool }

// insertEventTx writes one outbox event inside the domain transaction.
func insertEventTx(ctx context.Context, tx pgx.Tx, event ticketing.Event) error {
	if event.EventID == "" || event.Topic == "" || event.EventType == "" || event.SubjectID == "" || event.CorrelationID == "" {
		return errors.New("outbox event identifiers are required")
	}
	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO ferry_outbox (event_id, topic, subject_id, event_type, payload, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		event.EventID, event.Topic, event.SubjectID, event.EventType, payload, event.CorrelationID); err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}

// AppendEvent writes one standalone outbox event.
func (store *PostgresStore) AppendEvent(ctx context.Context, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin event transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// Pass products
// ---------------------------------------------------------------------------

// CreatePassProduct inserts one product (fail-closed validation upstream).
func (store *PostgresStore) CreatePassProduct(ctx context.Context, product PassProduct) error {
	_, err := store.pool.Exec(ctx,
		`INSERT INTO pass_products (product_id, kind, scope_type, scope_ref, price_ngn_minor, operator_id, active)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)`,
		product.ProductID, product.Kind, product.ScopeType, product.ScopeRef,
		product.PriceNGNMinor, product.OperatorID, product.Active)
	if err != nil {
		return fmt.Errorf("insert pass product: %w", err)
	}
	return nil
}

// GetPassProduct loads one product.
func (store *PostgresStore) GetPassProduct(ctx context.Context, productID string) (PassProduct, error) {
	var product PassProduct
	var operatorID, scopeRef *string
	err := store.pool.QueryRow(ctx,
		`SELECT product_id, kind, scope_type, scope_ref, price_ngn_minor, operator_id, active, created_at
		 FROM pass_products WHERE product_id = $1`, productID).
		Scan(&product.ProductID, &product.Kind, &product.ScopeType, &scopeRef, &product.PriceNGNMinor,
			&operatorID, &product.Active, &product.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PassProduct{}, ErrNotFound
		}
		return PassProduct{}, fmt.Errorf("load pass product: %w", err)
	}
	if scopeRef != nil {
		product.ScopeRef = *scopeRef
	}
	if operatorID != nil {
		product.OperatorID = *operatorID
	}
	return product, nil
}

// ListPassProducts returns products, optionally only active ones.
func (store *PostgresStore) ListPassProducts(ctx context.Context, activeOnly bool) ([]PassProduct, error) {
	query := `SELECT product_id, kind, scope_type, scope_ref, price_ngn_minor, operator_id, active, created_at FROM pass_products`
	if activeOnly {
		query += ` WHERE active`
	}
	query += ` ORDER BY created_at`
	rows, err := store.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list pass products: %w", err)
	}
	defer rows.Close()
	products := make([]PassProduct, 0)
	for rows.Next() {
		var product PassProduct
		var operatorID, scopeRef *string
		if err := rows.Scan(&product.ProductID, &product.Kind, &product.ScopeType, &scopeRef,
			&product.PriceNGNMinor, &operatorID, &product.Active, &product.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pass product: %w", err)
		}
		if scopeRef != nil {
			product.ScopeRef = *scopeRef
		}
		if operatorID != nil {
			product.OperatorID = *operatorID
		}
		products = append(products, product)
	}
	return products, rows.Err()
}

// ---------------------------------------------------------------------------
// Pass purchase saga
// ---------------------------------------------------------------------------

// GetPassPurchaseByIdempotency resolves one idempotency key.
func (store *PostgresStore) GetPassPurchaseByIdempotency(ctx context.Context, idempotencyKey string) (PassPurchase, error) {
	return scanPassPurchase(store.pool.QueryRow(ctx,
		`SELECT `+passPurchaseColumns+` FROM pass_purchases WHERE idempotency_key = $1`, idempotencyKey))
}

// GetPassPurchase loads one purchase by id.
func (store *PostgresStore) GetPassPurchase(ctx context.Context, purchaseID string) (PassPurchase, error) {
	return scanPassPurchase(store.pool.QueryRow(ctx,
		`SELECT `+passPurchaseColumns+` FROM pass_purchases WHERE purchase_id = $1`, purchaseID))
}

const passPurchaseColumns = `purchase_id, product_id, pass_id, owner_digest, price_ngn_minor, channel,
	agent_id, account_id, state, version, ledger_reserve_id, ledger_post_id,
	purchaser_principal, correlation_id, idempotency_key, created_at, updated_at`

func scanPassPurchase(row pgx.Row) (PassPurchase, error) {
	var purchase PassPurchase
	var passID, agentID, accountID, reserveID, postID *string
	err := row.Scan(&purchase.PurchaseID, &purchase.ProductID, &passID, &purchase.OwnerDigest,
		&purchase.PriceNGNMinor, &purchase.Channel, &agentID, &accountID, &purchase.State, &purchase.Version,
		&reserveID, &postID, &purchase.PurchaserPrincipal, &purchase.CorrelationID, &purchase.IdempotencyKey,
		&purchase.CreatedAt, &purchase.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PassPurchase{}, ErrNotFound
		}
		return PassPurchase{}, fmt.Errorf("load pass purchase: %w", err)
	}
	if passID != nil {
		purchase.PassID = *passID
	}
	if agentID != nil {
		purchase.AgentID = *agentID
	}
	if accountID != nil {
		purchase.AccountID = *accountID
	}
	if reserveID != nil {
		purchase.LedgerReserveID = *reserveID
	}
	if postID != nil {
		purchase.LedgerPostID = *postID
	}
	return purchase, nil
}

// InsertPassPurchase persists the RESERVED purchase with its outbox event in
// one transaction. The idempotency key is globally unique; a duplicate key
// surfaces as ErrIdempotencyConflict.
func (store *PostgresStore) InsertPassPurchase(ctx context.Context, purchase PassPurchase, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin pass purchase transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO pass_purchases (purchase_id, product_id, owner_digest, price_ngn_minor, channel,
		     agent_id, account_id, state, version, ledger_reserve_id, purchaser_principal, correlation_id, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, 1, NULLIF($9, ''), $10, $11, $12)`,
		purchase.PurchaseID, purchase.ProductID, purchase.OwnerDigest, purchase.PriceNGNMinor, purchase.Channel,
		purchase.AgentID, purchase.AccountID, purchase.State, purchase.LedgerReserveID,
		purchase.PurchaserPrincipal, purchase.CorrelationID, purchase.IdempotencyKey); err != nil {
		return fmt.Errorf("insert pass purchase: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit pass purchase: %w", err)
	}
	return nil
}

// MarkPassPurchasePaid transitions RESERVED -> PAID with the ledger post.
func (store *PostgresStore) MarkPassPurchasePaid(ctx context.Context, purchaseID string, version int64, ledgerPostID string, event ticketing.Event) (PassPurchase, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return PassPurchase{}, fmt.Errorf("begin pass payment transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`UPDATE pass_purchases SET state = $2, version = version + 1, ledger_post_id = $3, updated_at = now()
		 WHERE purchase_id = $1 AND version = $4 AND state = $5`,
		purchaseID, PurchasePaid, ledgerPostID, version, PurchaseReserved)
	if err != nil {
		return PassPurchase{}, fmt.Errorf("mark pass purchase paid: %w", err)
	}
	if result.RowsAffected() != 1 {
		return PassPurchase{}, fmt.Errorf("pass purchase version conflict on %s: %w", purchaseID, ErrInvalidTransition)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return PassPurchase{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PassPurchase{}, fmt.Errorf("commit pass payment: %w", err)
	}
	return store.GetPassPurchase(ctx, purchaseID)
}

// IssuePass transitions PAID -> ISSUED, inserting the ACTIVE pass in the
// same transaction (a paid pass purchase always yields its pass atomically).
func (store *PostgresStore) IssuePass(ctx context.Context, purchaseID string, version int64, pass Pass, event ticketing.Event) (Pass, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Pass{}, fmt.Errorf("begin pass issue transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO passes (pass_id, product_id, owner_digest, valid_from, valid_to, status, purchase_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		pass.PassID, pass.ProductID, pass.OwnerDigest, pass.ValidFrom, pass.ValidTo, pass.Status, pass.PurchaseID); err != nil {
		return Pass{}, fmt.Errorf("insert pass: %w", err)
	}
	result, err := tx.Exec(ctx,
		`UPDATE pass_purchases SET state = $2, version = version + 1, pass_id = $3, updated_at = now()
		 WHERE purchase_id = $1 AND version = $4 AND state = $5`,
		purchaseID, PurchaseIssued, pass.PassID, version, PurchasePaid)
	if err != nil {
		return Pass{}, fmt.Errorf("mark pass purchase issued: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Pass{}, fmt.Errorf("pass purchase version conflict on %s: %w", purchaseID, ErrInvalidTransition)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return Pass{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Pass{}, fmt.Errorf("commit pass issue: %w", err)
	}
	pass.Version = 1
	return pass, nil
}

// GetPass loads one pass.
func (store *PostgresStore) GetPass(ctx context.Context, passID string) (Pass, error) {
	var pass Pass
	err := store.pool.QueryRow(ctx,
		`SELECT pass_id, product_id, owner_digest, valid_from, valid_to, status, purchase_id, version, created_at, updated_at
		 FROM passes WHERE pass_id = $1`, passID).
		Scan(&pass.PassID, &pass.ProductID, &pass.OwnerDigest, &pass.ValidFrom, &pass.ValidTo,
			&pass.Status, &pass.PurchaseID, &pass.Version, &pass.CreatedAt, &pass.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Pass{}, ErrNotFound
		}
		return Pass{}, fmt.Errorf("load pass: %w", err)
	}
	return pass, nil
}

// TransitionPass applies one pass status transition with optimistic
// concurrency plus the audit event, and records the revocation blocklist row
// when transitioning to REVOKED — all in one transaction.
func (store *PostgresStore) TransitionPass(ctx context.Context, passID string, version int64, from []string, to, reason string, event ticketing.Event) (Pass, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Pass{}, fmt.Errorf("begin pass transition transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx,
		`UPDATE passes SET status = $2, version = version + 1, updated_at = now()
		 WHERE pass_id = $1 AND version = $3 AND status = ANY($4)`,
		passID, to, version, from)
	if err != nil {
		return Pass{}, fmt.Errorf("transition pass: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Pass{}, fmt.Errorf("pass %s version/state conflict: %w", passID, ErrInvalidTransition)
	}
	if to == PassStatusRevoked {
		if _, err := tx.Exec(ctx,
			`INSERT INTO pass_revocations (pass_id, reason) VALUES ($1, $2)
			 ON CONFLICT (pass_id) DO NOTHING`, passID, reason); err != nil {
			return Pass{}, fmt.Errorf("record pass revocation: %w", err)
		}
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return Pass{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Pass{}, fmt.Errorf("commit pass transition: %w", err)
	}
	return store.GetPass(ctx, passID)
}

// ListActivePassesExpiringBefore returns up to limit ACTIVE passes whose
// validity has elapsed (expiry sweep input).
func (store *PostgresStore) ListActivePassesExpiringBefore(ctx context.Context, cutoff time.Time, limit int) ([]Pass, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT pass_id, product_id, owner_digest, valid_from, valid_to, status, purchase_id, version, created_at, updated_at
		 FROM passes WHERE status = 'ACTIVE' AND valid_to <= $1 ORDER BY valid_to LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("list expiring passes: %w", err)
	}
	defer rows.Close()
	passes := make([]Pass, 0)
	for rows.Next() {
		var pass Pass
		if err := rows.Scan(&pass.PassID, &pass.ProductID, &pass.OwnerDigest, &pass.ValidFrom, &pass.ValidTo,
			&pass.Status, &pass.PurchaseID, &pass.Version, &pass.CreatedAt, &pass.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan expiring pass: %w", err)
		}
		passes = append(passes, pass)
	}
	return passes, rows.Err()
}

// ---------------------------------------------------------------------------
// Validation keys and blocklist
// ---------------------------------------------------------------------------

// ValidationKeyRow is one pass_validation_keys row.
type ValidationKeyRow struct {
	Epoch        int
	Kid          string
	PublicKeyHex string
	Status       string
	RotatedAt    *time.Time
}

// EnsureValidationKeyDirectory provisions the signing epoch at boot: the
// configured epoch becomes CURRENT; any other CURRENT key is demoted to
// PREVIOUS (rotation grace). Older keys are never deleted — devices with
// stale caches keep verifying until their next sync.
func (store *PostgresStore) EnsureValidationKeyDirectory(ctx context.Context, epoch int, kid, publicKeyHex string) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin key directory transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE pass_validation_keys SET status = 'PREVIOUS', rotated_at = now()
		 WHERE status = 'CURRENT' AND epoch <> $1`, epoch); err != nil {
		return fmt.Errorf("demote stale validation keys: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO pass_validation_keys (epoch, kid, public_key_hex, status)
		 VALUES ($1, $2, $3, 'CURRENT')
		 ON CONFLICT (epoch) DO UPDATE SET status = 'CURRENT', kid = EXCLUDED.kid, public_key_hex = EXCLUDED.public_key_hex`,
		epoch, kid, publicKeyHex); err != nil {
		return fmt.Errorf("upsert current validation key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit key directory: %w", err)
	}
	return nil
}

// ListValidationKeys returns the distributable directory (CURRENT + PREVIOUS).
func (store *PostgresStore) ListValidationKeys(ctx context.Context) ([]ValidationKeyRow, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT epoch, kid, public_key_hex, status, rotated_at FROM pass_validation_keys
		 WHERE status IN ('CURRENT', 'PREVIOUS') ORDER BY epoch DESC`)
	if err != nil {
		return nil, fmt.Errorf("list validation keys: %w", err)
	}
	defer rows.Close()
	keys := make([]ValidationKeyRow, 0)
	for rows.Next() {
		var key ValidationKeyRow
		if err := rows.Scan(&key.Epoch, &key.Kid, &key.PublicKeyHex, &key.Status, &key.RotatedAt); err != nil {
			return nil, fmt.Errorf("scan validation key: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// BlocklistEntry is one revoked pass in a delta page.
type BlocklistEntry struct {
	PassID    string
	RevokedAt time.Time
}

// ListRevocationsSince returns up to limit revocations strictly after the
// (revoked_at, pass_id) cursor, ordered for keyset pagination.
func (store *PostgresStore) ListRevocationsSince(ctx context.Context, since time.Time, sincePassID string, limit int) ([]BlocklistEntry, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT pass_id, revoked_at FROM pass_revocations
		 WHERE (revoked_at, pass_id) > ($1, $2) ORDER BY revoked_at, pass_id LIMIT $3`,
		since, sincePassID, limit)
	if err != nil {
		return nil, fmt.Errorf("list revocations: %w", err)
	}
	defer rows.Close()
	entries := make([]BlocklistEntry, 0)
	for rows.Next() {
		var entry BlocklistEntry
		if err := rows.Scan(&entry.PassID, &entry.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan revocation: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// RecordPassRide inserts one conductor-admitted pass ride (ride_id is the
// scan id, so replays dedupe by construction). Returns false on replay.
func (store *PostgresStore) RecordPassRide(ctx context.Context, tx pgx.Tx, rideID, passID, operatorID, routeReference, deviceID string, admittedAt time.Time) (bool, error) {
	result, err := tx.Exec(ctx,
		`INSERT INTO pass_rides (ride_id, pass_id, operator_id, route_reference, device_id, admitted_at)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (ride_id) DO NOTHING`,
		rideID, passID, operatorID, routeReference, deviceID, admittedAt)
	if err != nil {
		return false, fmt.Errorf("record pass ride: %w", err)
	}
	return result.RowsAffected() == 1, nil
}
