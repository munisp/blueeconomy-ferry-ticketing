package fare

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

// BatchScan is one scan inside a store-and-forward batch. The device signs
// each scan and the batch envelope; signatures are STORED for audit and
// verified once the device-management plane lands (TODO W-FEAT-3) — for now
// the service authenticates the conductor at the JWT service level and never
// fabricates device identity.
type BatchScan struct {
	ScanID         string    `json:"scanId"`
	Kind           string    `json:"kind,omitempty"` // TICKET | PASS | ACCOUNT_DEBIT; empty = detect from artifact magic
	Artifact       string    `json:"artifact"`       // BET1/BFP1 token, or instrument token_ref for ACCOUNT_DEBIT
	AmountNGNMinor int64     `json:"amountNgnMinor,omitempty"`
	RouteReference string    `json:"routeReference,omitempty"`
	ScannedAt      time.Time `json:"scannedAt"`
	Signature      string    `json:"signature"` // TODO W-FEAT-3: verify against device key registry
}

// BatchRequest is one conductor batch upload.
type BatchRequest struct {
	DeviceID       string
	BatchID        string
	OperatorID     string
	BatchSignature string // TODO W-FEAT-3: verify against device key registry
	Scans          []BatchScan
	Principal      string
	CorrelationID  string
}

// BatchResult is the upload outcome (also the replay view).
type BatchResult struct {
	Batch    ConductorBatch  `json:"batch"`
	Scans    []ConductorScan `json:"scans"`
	Replayed bool            `json:"replayed"`
}

// BoardingConsumer is the first-scan-wins boarding boundary (implemented by
// ticketing.PostgresStore).
type BoardingConsumer interface {
	ConsumeBoarding(ctx context.Context, operatorID, ticketID, boardedBy, artifactKid string) (bool, error)
	GetTicket(ctx context.Context, ticketID string) (ticketing.Ticket, error)
}

// ConductorService ingests store-and-forward scan batches: durable per-scan
// idempotency, first-scan-wins preserved server-side, conflicts routed to
// REVIEW_REQUIRED (never blocking embarkation at the gangway — the device
// admitted offline; the server reconciles), and offline debits settled
// against per-device caps (Advisory §9.5).
type ConductorService struct {
	store       *PostgresStore
	boarding    BoardingConsumer
	verifier    *ticketproof.Verifier
	validation  *ValidationService
	accounts    AccountLedger
	now         func() time.Time
}

// NewConductorService fails closed on any missing dependency.
func NewConductorService(store *PostgresStore, boarding BoardingConsumer, verifier *ticketproof.Verifier, validation *ValidationService, accounts AccountLedger) (*ConductorService, error) {
	if store == nil || boarding == nil || validation == nil {
		return nil, errors.New("fare store, boarding consumer and validation service are required")
	}
	if verifier == nil {
		return nil, errors.New("ticket artifact verifier is required (fail-closed)")
	}
	if accounts == nil {
		return nil, errors.New("account ledger is required (fail-closed)")
	}
	return &ConductorService{store: store, boarding: boarding, verifier: verifier, validation: validation,
		accounts: accounts, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SubmitBatch ingests one batch. Replaying the same (device, batch) pair
// returns the stored outcome unchanged — no double admits, no double debits.
func (service *ConductorService) SubmitBatch(ctx context.Context, request BatchRequest) (BatchResult, error) {
	if strings.TrimSpace(request.DeviceID) == "" || strings.TrimSpace(request.BatchID) == "" || strings.TrimSpace(request.OperatorID) == "" {
		return BatchResult{}, errors.New("device id, batch id and operator id are required")
	}
	if strings.TrimSpace(request.BatchSignature) == "" {
		return BatchResult{}, errors.New("batch signature is required")
	}
	if len(request.Scans) == 0 || len(request.Scans) > 500 {
		return BatchResult{}, errors.New("batch must carry 1..500 scans")
	}
	for _, scan := range request.Scans {
		if strings.TrimSpace(scan.ScanID) == "" || strings.TrimSpace(scan.Artifact) == "" {
			return BatchResult{}, errors.New("every scan requires a scan id and an artifact")
		}
		if scan.ScannedAt.IsZero() {
			return BatchResult{}, errors.New("every scan requires a scanned_at timestamp")
		}
	}
	batch := ConductorBatch{
		DeviceID:       request.DeviceID,
		BatchID:        request.BatchID,
		OperatorID:     request.OperatorID,
		ScanCount:      len(request.Scans),
		BatchSignature: request.BatchSignature,
	}
	created, err := service.store.InsertConductorBatch(ctx, batch)
	if err != nil {
		return BatchResult{}, err
	}
	if !created {
		return service.batchResult(ctx, request.DeviceID, request.BatchID, true)
	}
	admitted, denied, review := 0, 0, 0
	for _, scan := range request.Scans {
		outcome, err := service.processScan(ctx, request, scan)
		if err != nil {
			return BatchResult{}, fmt.Errorf("process scan %s: %w", scan.ScanID, err)
		}
		switch outcome.Result {
		case ScanAdmitted:
			admitted++
		case ScanDenied:
			denied++
		case ScanReviewRequired:
			review++
		}
	}
	if err := service.store.FinalizeConductorBatch(ctx, request.DeviceID, request.BatchID, admitted, denied, review,
		ticketing.Event{
			EventID:       uuid.NewString(),
			Topic:         TopicFare,
			SubjectID:     request.BatchID,
			EventType:     EventConductorBatchProcessed,
			CorrelationID: correlationOrNew(request.CorrelationID),
			Payload: map[string]any{
				"batch_id":        request.BatchID,
				"device_id":       request.DeviceID,
				"operator_id":     request.OperatorID,
				"scan_count":      len(request.Scans),
				"admitted":        admitted,
				"denied":          denied,
				"review_required": review,
				"principal_id":    request.Principal,
			},
		}); err != nil {
		return BatchResult{}, err
	}
	return service.batchResult(ctx, request.DeviceID, request.BatchID, false)
}

// batchResult loads the stored outcome view.
func (service *ConductorService) batchResult(ctx context.Context, deviceID, batchID string, replayed bool) (BatchResult, error) {
	batch, err := service.store.GetConductorBatch(ctx, deviceID, batchID)
	if err != nil {
		return BatchResult{}, err
	}
	scans, err := service.store.ListScans(ctx, deviceID, batchID)
	if err != nil {
		return BatchResult{}, err
	}
	return BatchResult{Batch: batch, Scans: scans, Replayed: replayed}, nil
}

// processScan resolves one scan idempotently (the durable scan record is the
// dedupe boundary) and applies the artifact-kind semantics.
func (service *ConductorService) processScan(ctx context.Context, request BatchRequest, scan BatchScan) (ConductorScan, error) {
	if stored, err := service.store.GetScan(ctx, request.DeviceID, scan.ScanID); err == nil {
		return stored, nil // durable dedupe: replay returns the stored outcome
	} else if !errors.Is(err, ErrNotFound) {
		return ConductorScan{}, err
	}
	kind := strings.ToUpper(strings.TrimSpace(scan.Kind))
	if kind == "" {
		kind = detectArtifactKind(scan.Artifact)
	}
	record := ConductorScan{
		DeviceID:     request.DeviceID,
		ScanID:       scan.ScanID,
		BatchID:      request.BatchID,
		ArtifactKind: kind,
		OperatorID:   request.OperatorID,
		ScannedAt:    scan.ScannedAt,
	}
	var err error
	switch kind {
	case "TICKET":
		record, err = service.processTicketScan(ctx, request, scan, record)
	case "PASS":
		record, err = service.processPassScan(ctx, request, scan, record)
	case "ACCOUNT_DEBIT":
		record, err = service.processOfflineDebit(ctx, request, scan, record)
	case "NFC_TAP":
		record, err = service.processTapScan(ctx, request, scan, record)
	default:
		record.Result = ScanDenied
		record.DenyReason = "unknown_artifact_kind"
	}
	if err != nil {
		return ConductorScan{}, err
	}
	tx, err := service.store.Pool().Begin(ctx)
	if err != nil {
		return ConductorScan{}, err
	}
	defer tx.Rollback(ctx)
	inserted, err := service.store.RecordScanTx(ctx, tx, record)
	if err != nil {
		return ConductorScan{}, err
	}
	if !inserted {
		return service.store.GetScan(ctx, request.DeviceID, scan.ScanID)
	}
	if err := tx.Commit(ctx); err != nil {
		return ConductorScan{}, err
	}
	return record, nil
}

// detectArtifactKind reads the wire magic inside the base64 token.
func detectArtifactKind(artifact string) string {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(artifact))
	if err != nil || len(raw) < 4 {
		return "UNKNOWN"
	}
	switch string(raw[:4]) {
	case ticketproof.WireFormatVersion:
		return "TICKET"
	case "BFP1":
		return "PASS"
	}
	return "UNKNOWN"
}

// processTicketScan consumes a seat-ticket boarding first-scan-wins. Offline
// scans are verified for AUTHENTICITY at the scan instant (the rotating
// window code is an online-gate check; it cannot validate replayed history).
func (service *ConductorService) processTicketScan(ctx context.Context, request BatchRequest, scan BatchScan, record ConductorScan) (ConductorScan, error) {
	payload, err := service.verifier.VerifyAuthenticity(strings.TrimSpace(scan.Artifact), scan.ScannedAt)
	if err != nil {
		record.Result = ScanDenied
		record.DenyReason = ticketproof.FailureReason(err)
		return record, nil
	}
	record.SubjectID = payload.TicketID
	consumed, err := service.boarding.ConsumeBoarding(ctx, request.OperatorID, payload.TicketID,
		"device:"+request.DeviceID, payload.KeyID)
	if err != nil {
		return record, fmt.Errorf("consume boarding: %w", err)
	}
	if consumed {
		record.Result = ScanAdmitted
		return record, nil
	}
	ticket, err := service.boarding.GetTicket(ctx, payload.TicketID)
	if err != nil {
		record.Result = ScanDenied
		record.DenyReason = "unknown_ticket"
		return record, nil
	}
	if ticket.OperatorID != request.OperatorID {
		// Same-token-two-vessels: the advisory routes this to review and
		// never blocks embarkation retroactively.
		record.Result = ScanReviewRequired
		record.DenyReason = "cross_operator_presentation"
		return record, nil
	}
	if ticket.BoardedAt != nil {
		record.Result = ScanDuplicate
		record.DenyReason = "boarding_already_consumed"
		return record, nil
	}
	record.Result = ScanDenied
	record.DenyReason = "not_boardable"
	return record, nil
}

// processPassScan validates a pass artifact and records the ride (the
// settlement attribution input).
func (service *ConductorService) processPassScan(ctx context.Context, request BatchRequest, scan BatchScan, record ConductorScan) (ConductorScan, error) {
	decision := service.validation.Validate(ctx, scan.Artifact, scan.RouteReference)
	record.SubjectID = decision.PassID
	if !decision.Admit {
		record.Result = ScanDenied
		record.DenyReason = decision.Reason
		return record, nil
	}
	tx, err := service.store.Pool().Begin(ctx)
	if err != nil {
		return record, err
	}
	defer tx.Rollback(ctx)
	if _, err := service.store.RecordPassRide(ctx, tx, scan.ScanID, decision.PassID, request.OperatorID,
		scan.RouteReference, request.DeviceID, scan.ScannedAt); err != nil {
		return record, err
	}
	if err := tx.Commit(ctx); err != nil {
		return record, err
	}
	record.Result = ScanAdmitted
	return record, nil
}

// processOfflineDebit settles one device-admitted offline debit against the
// per-device caps and the account's ledger balance. Over-cap scans route to
// REVIEW (no settlement); cluster-declined debits are the liability-queue
// DECLINED outcome (Advisory §9.5: the government's loss, made visible).
// processTapScan handles one NFC tap upload (PRA-133): parse the TLV
// payload, verify the instrument signature against the enrolled Ed25519 key
// (the same check the device ran offline), spend the monotonic tap counter
// (anti-replay), then settle through the identical capped offline-debit
// path (per-tx/daily caps, settle-on-reconnect, decline liability).
func (service *ConductorService) processTapScan(ctx context.Context, request BatchRequest, scan BatchScan, record ConductorScan) (ConductorScan, error) {
	payload, err := ParseTapPayload(scan.Artifact)
	if err != nil {
		record.Result = ScanDenied
		record.DenyReason = "malformed_tap"
		return record, nil
	}
	instrument, err := service.store.GetInstrumentByToken(ctx, payload.TokenRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			record.Result = ScanDenied
			record.DenyReason = "unknown_instrument"
			return record, nil
		}
		return record, err
	}
	if instrument.Kind != "NFC_TAP" || instrument.Status != "ACTIVE" || instrument.PublicKeyHex == "" {
		record.Result = ScanDenied
		record.DenyReason = "instrument_not_tap_enrolled"
		return record, nil
	}
	if err := VerifyTapSignature(instrument.PublicKeyHex, payload); err != nil {
		record.Result = ScanDenied
		record.DenyReason = "invalid_tap_signature"
		return record, nil
	}
	claimed, err := service.store.ClaimTapCounter(ctx, payload.TokenRef, payload.Counter)
	if err != nil {
		return record, err
	}
	if !claimed {
		record.Result = ScanDenied
		record.DenyReason = "tap_replayed"
		return record, nil
	}
	// Verified tap: settle as a capped offline debit (same money semantics).
	debitScan := scan
	debitScan.Artifact = payload.TokenRef
	debitScan.AmountNGNMinor = payload.AmountMinor
	debitScan.ScannedAt = payload.TappedAt
	return service.processOfflineDebit(ctx, request, debitScan, record)
}

func (service *ConductorService) processOfflineDebit(ctx context.Context, request BatchRequest, scan BatchScan, record ConductorScan) (ConductorScan, error) {
	// Offline-debit settlement span: cap check + ledger debit as one traced
	// unit (Advisory §9.5 outcomes are attributes, never swallowed).
	ctx, span := tracer().Start(ctx, "ferry.offline_debit.settlement",
		trace.WithAttributes(
			attribute.String("ferry.device_id", request.DeviceID),
			attribute.String("ferry.operator_id", request.OperatorID),
			attribute.Int64("ferry.amount_ngn_minor", scan.AmountNGNMinor),
		))
	defer span.End()
	caps, err := service.store.GetDeviceCaps(ctx, request.DeviceID)
	if err != nil {
		if errors.Is(err, ErrDeviceNotProvisioned) {
			record.Result = ScanDenied
			record.DenyReason = "device_not_provisioned"
			return record, nil
		}
		return record, err
	}
	if !caps.Active || caps.OperatorID != request.OperatorID {
		record.Result = ScanDenied
		record.DenyReason = "device_not_provisioned"
		return record, nil
	}
	if scan.AmountNGNMinor <= 0 {
		record.Result = ScanDenied
		record.DenyReason = "amount_required"
		return record, nil
	}
	reviewReason := ""
	if scan.AmountNGNMinor > caps.PerTxCapMinor {
		reviewReason = "over_per_tx_cap"
	} else {
		tx, err := service.store.Pool().Begin(ctx)
		if err != nil {
			return record, err
		}
		dayStart := DayPeriodStart(service.now())
		settled, sumErr := service.store.SettledOfflineDebitTotal(ctx, tx, request.DeviceID, dayStart)
		_ = tx.Rollback(ctx)
		if sumErr != nil {
			return record, sumErr
		}
		if settled+scan.AmountNGNMinor > caps.DailyCapMinor {
			reviewReason = "over_daily_cap"
		}
	}
	account, err := service.store.GetFareAccountByInstrument(ctx, strings.TrimSpace(scan.Artifact))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			record.Result = ScanDenied
			record.DenyReason = "unknown_instrument"
			return record, nil
		}
		return record, err
	}
	record.SubjectID = account.AccountID
	if account.Status != "ACTIVE" {
		record.Result = ScanDenied
		record.DenyReason = "account_not_active"
		return record, nil
	}
	if reviewReason != "" {
		if err := service.recordDebitOutcome(ctx, OfflineDebit{
			DebitID: scan.ScanID, AccountID: account.AccountID, DeviceID: request.DeviceID,
			OperatorID: request.OperatorID, AmountNGNMinor: scan.AmountNGNMinor,
			State: DebitReview, DeclineReason: reviewReason, ScannedAt: scan.ScannedAt,
		}); err != nil {
			return record, err
		}
		record.Result = ScanReviewRequired
		record.DenyReason = reviewReason
		return record, nil
	}
	transferID, err := service.accounts.DebitAccount(ctx, scan.ScanID, account.LedgerAccountID, scan.AmountNGNMinor)
	if err != nil {
		// Decline-after-sync: the ledger rejected the debit (insufficient
		// balance or ledger fault). Record the liability, never fake success.
		if recordErr := service.recordDebitOutcome(ctx, OfflineDebit{
			DebitID: scan.ScanID, AccountID: account.AccountID, DeviceID: request.DeviceID,
			OperatorID: request.OperatorID, AmountNGNMinor: scan.AmountNGNMinor,
			State: DebitDeclined, DeclineReason: "ledger_declined", ScannedAt: scan.ScannedAt,
		}); recordErr != nil {
			return record, recordErr
		}
		_ = service.store.AppendEvent(ctx, ticketing.Event{
			EventID: uuid.NewString(), Topic: TopicFare, SubjectID: scan.ScanID,
			EventType: EventOfflineDebitDeclined, CorrelationID: correlationOrNew(request.CorrelationID),
			Payload: map[string]any{
				"scan_id": scan.ScanID, "device_id": request.DeviceID, "account_id": account.AccountID,
				"amount_ngn_minor": scan.AmountNGNMinor, "reason": "ledger_declined",
			},
		})
		record.Result = ScanDenied
		record.DenyReason = "debit_declined"
		return record, nil
	}
	now := service.now()
	if err := service.settleDebitOutcome(ctx, OfflineDebit{
		DebitID: scan.ScanID, AccountID: account.AccountID, DeviceID: request.DeviceID,
		OperatorID: request.OperatorID, AmountNGNMinor: scan.AmountNGNMinor,
		State: DebitSettled, LedgerTransferID: transferID, ScannedAt: scan.ScannedAt, SettledAt: &now,
	}); err != nil {
		return record, err
	}
	_ = service.store.AppendEvent(ctx, ticketing.Event{
		EventID: uuid.NewString(), Topic: TopicFare, SubjectID: scan.ScanID,
		EventType: EventOfflineDebitSettled, CorrelationID: correlationOrNew(request.CorrelationID),
		Payload: map[string]any{
			"scan_id": scan.ScanID, "device_id": request.DeviceID, "account_id": account.AccountID,
			"amount_ngn_minor": scan.AmountNGNMinor, "ledger_transfer_id": transferID,
		},
	})
	record.Result = ScanAdmitted
	return record, nil
}

// recordDebitOutcome persists a non-settled debit outcome.
func (service *ConductorService) recordDebitOutcome(ctx context.Context, debit OfflineDebit) error {
	tx, err := service.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := service.store.InsertOfflineDebitTx(ctx, tx, debit); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// settleDebitOutcome persists the settled debit and the balance read-model
// adjustment in one transaction.
func (service *ConductorService) settleDebitOutcome(ctx context.Context, debit OfflineDebit) error {
	tx, err := service.store.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := service.store.InsertOfflineDebitTx(ctx, tx, debit); err != nil {
		return err
	}
	if err := service.store.AdjustCachedBalance(ctx, tx, debit.AccountID, -debit.AmountNGNMinor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func correlationOrNew(correlationID string) string {
	if correlationID == "" {
		return uuid.NewString()
	}
	return correlationID
}
