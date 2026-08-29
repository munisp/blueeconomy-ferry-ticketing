package fare

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// ConductorBatch is one uploaded store-and-forward batch.
type ConductorBatch struct {
	DeviceID       string
	BatchID        string
	OperatorID     string
	ScanCount      int
	Admitted       int
	Denied         int
	ReviewRequired int
	BatchSignature string
	ReceivedAt     time.Time
	ProcessedAt    *time.Time
}

// ConductorScan is one deduped scan record with its outcome.
type ConductorScan struct {
	DeviceID     string
	ScanID       string
	BatchID      string
	ArtifactKind string
	SubjectID    string
	OperatorID   string
	Result       string
	DenyReason   string
	ScannedAt    time.Time
	ProcessedAt  time.Time
}

// InsertConductorBatch records the batch envelope; created is false when the
// (device, batch) pair already exists (idempotent batch replay).
func (store *PostgresStore) InsertConductorBatch(ctx context.Context, batch ConductorBatch) (created bool, err error) {
	result, err := store.pool.Exec(ctx,
		`INSERT INTO conductor_batches (device_id, batch_id, operator_id, scan_count, batch_signature)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (device_id, batch_id) DO NOTHING`,
		batch.DeviceID, batch.BatchID, batch.OperatorID, batch.ScanCount, batch.BatchSignature)
	if err != nil {
		return false, fmt.Errorf("insert conductor batch: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// GetConductorBatch loads one batch.
func (store *PostgresStore) GetConductorBatch(ctx context.Context, deviceID, batchID string) (ConductorBatch, error) {
	var batch ConductorBatch
	err := store.pool.QueryRow(ctx,
		`SELECT device_id, batch_id, operator_id, scan_count, admitted, denied, review_required,
		        batch_signature, received_at, processed_at
		 FROM conductor_batches WHERE device_id = $1 AND batch_id = $2`, deviceID, batchID).
		Scan(&batch.DeviceID, &batch.BatchID, &batch.OperatorID, &batch.ScanCount, &batch.Admitted,
			&batch.Denied, &batch.ReviewRequired, &batch.BatchSignature, &batch.ReceivedAt, &batch.ProcessedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConductorBatch{}, ErrNotFound
		}
		return ConductorBatch{}, fmt.Errorf("load conductor batch: %w", err)
	}
	return batch, nil
}

// RecordScanTx inserts one scan outcome inside an open transaction; inserted
// is false when the (device, scan) pair already exists (idempotent per-scan
// dedupe — replays return the stored outcome).
func (store *PostgresStore) RecordScanTx(ctx context.Context, tx pgx.Tx, scan ConductorScan) (inserted bool, err error) {
	result, err := tx.Exec(ctx,
		`INSERT INTO conductor_scans (device_id, scan_id, batch_id, artifact_kind, subject_id, operator_id, result, deny_reason, scanned_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (device_id, scan_id) DO NOTHING`,
		scan.DeviceID, scan.ScanID, scan.BatchID, scan.ArtifactKind, scan.SubjectID, scan.OperatorID,
		scan.Result, scan.DenyReason, scan.ScannedAt)
	if err != nil {
		return false, fmt.Errorf("record conductor scan: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// GetScan loads one recorded scan outcome.
func (store *PostgresStore) GetScan(ctx context.Context, deviceID, scanID string) (ConductorScan, error) {
	var scan ConductorScan
	err := store.pool.QueryRow(ctx,
		`SELECT device_id, scan_id, batch_id, artifact_kind, subject_id, operator_id, result, deny_reason, scanned_at, processed_at
		 FROM conductor_scans WHERE device_id = $1 AND scan_id = $2`, deviceID, scanID).
		Scan(&scan.DeviceID, &scan.ScanID, &scan.BatchID, &scan.ArtifactKind, &scan.SubjectID,
			&scan.OperatorID, &scan.Result, &scan.DenyReason, &scan.ScannedAt, &scan.ProcessedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConductorScan{}, ErrNotFound
		}
		return ConductorScan{}, fmt.Errorf("load conductor scan: %w", err)
	}
	return scan, nil
}

// ListScans returns every scan of one batch in upload order.
func (store *PostgresStore) ListScans(ctx context.Context, deviceID, batchID string) ([]ConductorScan, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT device_id, scan_id, batch_id, artifact_kind, subject_id, operator_id, result, deny_reason, scanned_at, processed_at
		 FROM conductor_scans WHERE device_id = $1 AND batch_id = $2 ORDER BY processed_at, scan_id`,
		deviceID, batchID)
	if err != nil {
		return nil, fmt.Errorf("list conductor scans: %w", err)
	}
	defer rows.Close()
	scans := make([]ConductorScan, 0)
	for rows.Next() {
		var scan ConductorScan
		if err := rows.Scan(&scan.DeviceID, &scan.ScanID, &scan.BatchID, &scan.ArtifactKind, &scan.SubjectID,
			&scan.OperatorID, &scan.Result, &scan.DenyReason, &scan.ScannedAt, &scan.ProcessedAt); err != nil {
			return nil, fmt.Errorf("scan conductor scan: %w", err)
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

// FinalizeConductorBatch records the outcome counts and the audit event.
func (store *PostgresStore) FinalizeConductorBatch(ctx context.Context, deviceID, batchID string, admitted, denied, review int, event ticketing.Event) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin batch finalize transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`UPDATE conductor_batches SET admitted = $3, denied = $4, review_required = $5, processed_at = now()
		 WHERE device_id = $1 AND batch_id = $2`, deviceID, batchID, admitted, denied, review); err != nil {
		return fmt.Errorf("finalize conductor batch: %w", err)
	}
	if err := insertEventTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeviceCaps is the per-device offline debit provisioning (Advisory §9.5
// revenue-leakage control).
type DeviceCaps struct {
	DeviceID       string
	OperatorID     string
	PerTxCapMinor  int64
	DailyCapMinor  int64
	Active         bool
}

// GetDeviceCaps loads one device's provisioning.
func (store *PostgresStore) GetDeviceCaps(ctx context.Context, deviceID string) (DeviceCaps, error) {
	var caps DeviceCaps
	err := store.pool.QueryRow(ctx,
		`SELECT device_id, operator_id, per_tx_cap_minor, daily_cap_minor, active
		 FROM device_offline_caps WHERE device_id = $1`, deviceID).
		Scan(&caps.DeviceID, &caps.OperatorID, &caps.PerTxCapMinor, &caps.DailyCapMinor, &caps.Active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeviceCaps{}, ErrDeviceNotProvisioned
		}
		return DeviceCaps{}, fmt.Errorf("load device caps: %w", err)
	}
	return caps, nil
}

// SetDeviceCaps provisions or updates one device's offline caps.
func (store *PostgresStore) SetDeviceCaps(ctx context.Context, caps DeviceCaps) error {
	_, err := store.pool.Exec(ctx,
		`INSERT INTO device_offline_caps (device_id, operator_id, per_tx_cap_minor, daily_cap_minor, active)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (device_id) DO UPDATE SET per_tx_cap_minor = EXCLUDED.per_tx_cap_minor,
		     daily_cap_minor = EXCLUDED.daily_cap_minor, active = EXCLUDED.active`,
		caps.DeviceID, caps.OperatorID, caps.PerTxCapMinor, caps.DailyCapMinor, caps.Active)
	if err != nil {
		return fmt.Errorf("upsert device caps: %w", err)
	}
	return nil
}

// OfflineDebit is one settled/declined offline account debit.
type OfflineDebit struct {
	DebitID          string
	AccountID        string
	DeviceID         string
	OperatorID       string
	AmountNGNMinor   int64
	State            string
	LedgerTransferID string
	DeclineReason    string
	ScannedAt        time.Time
	SettledAt        *time.Time
}

// InsertOfflineDebitTx records one offline debit outcome inside an open
// transaction (debit_id is the scan id, so replays dedupe by construction).
func (store *PostgresStore) InsertOfflineDebitTx(ctx context.Context, tx pgx.Tx, debit OfflineDebit) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO offline_debits (debit_id, account_id, device_id, operator_id, amount_ngn_minor, state,
		     ledger_transfer_id, decline_reason, scanned_at, settled_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10)`,
		debit.DebitID, debit.AccountID, debit.DeviceID, debit.OperatorID, debit.AmountNGNMinor, debit.State,
		debit.LedgerTransferID, debit.DeclineReason, debit.ScannedAt, debit.SettledAt)
	if err != nil {
		return fmt.Errorf("insert offline debit: %w", err)
	}
	return nil
}

// SettledOfflineDebitTotal sums one device's settled offline debits since a
// timestamp (daily cap enforcement input).
func (store *PostgresStore) SettledOfflineDebitTotal(ctx context.Context, tx pgx.Tx, deviceID string, since time.Time) (int64, error) {
	var total int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount_ngn_minor), 0) FROM offline_debits
		 WHERE device_id = $1 AND state = $2 AND created_at >= $3`,
		deviceID, DebitSettled, since).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("sum device offline debits: %w", err)
	}
	return total, nil
}

// OfflineDebitReport is the settle-on-reconnect reconciliation view: what
// each device settled, what was declined after sync (the government-loss
// liability queue) and what awaits review.
type OfflineDebitReport struct {
	DeviceID         string `json:"deviceId"`
	SettledCount     int64   `json:"settledCount"`
	SettledMinor     int64   `json:"settledNgnMinor"`
	DeclinedCount    int64   `json:"declinedCount"`
	DeclinedMinor    int64   `json:"declinedNgnMinor"` // liability: declined after sync
	ReviewCount      int64   `json:"reviewCount"`
	ReviewMinor      int64   `json:"reviewNgnMinor"`
}

// OfflineDebitReconciliation aggregates offline debits per device over a window.
func (store *PostgresStore) OfflineDebitReconciliation(ctx context.Context, from, to time.Time) ([]OfflineDebitReport, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT device_id,
		        COUNT(*) FILTER (WHERE state = 'SETTLED'),
		        COALESCE(SUM(amount_ngn_minor) FILTER (WHERE state = 'SETTLED'), 0),
		        COUNT(*) FILTER (WHERE state = 'DECLINED'),
		        COALESCE(SUM(amount_ngn_minor) FILTER (WHERE state = 'DECLINED'), 0),
		        COUNT(*) FILTER (WHERE state = 'REVIEW'),
		        COALESCE(SUM(amount_ngn_minor) FILTER (WHERE state = 'REVIEW'), 0)
		 FROM offline_debits WHERE created_at >= $1 AND created_at < $2
		 GROUP BY device_id ORDER BY device_id`, from, to)
	if err != nil {
		return nil, fmt.Errorf("offline debit reconciliation: %w", err)
	}
	defer rows.Close()
	reports := make([]OfflineDebitReport, 0)
	for rows.Next() {
		var report OfflineDebitReport
		if err := rows.Scan(&report.DeviceID, &report.SettledCount, &report.SettledMinor,
			&report.DeclinedCount, &report.DeclinedMinor, &report.ReviewCount, &report.ReviewMinor); err != nil {
			return nil, fmt.Errorf("scan offline debit reconciliation: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}
