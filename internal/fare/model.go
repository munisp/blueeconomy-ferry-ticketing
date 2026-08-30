// Package fare implements BlueFare: the account-based fare system for the
// platform's water-transport layer (Citizen Services Advisory §4). It
// composes the existing booking spine — seat tickets, the two-phase
// TigerBeetle reserve/post saga, durable idempotency keys and the
// transactional outbox — rather than bypassing it:
//
//   - Period passes (DAY/WEEK/MONTH; route/zone/network scope) are purchased
//     through the same saga discipline as tickets (reserve -> pay -> issue,
//     replay-safe idempotency keys, outbox events in the same transaction).
//   - Account-based fare capping prices every paid single journey as
//     min(fare, cap remaining) under the accumulator row lock; fully capped
//     journeys issue valid zero-fare tickets. Money movements stay in
//     TigerBeetle (pending = hold, deterministic transfer IDs dedupe
//     cluster-side); the PG accumulator is the OLGP decision record updated
//     in the same saga step with its outbox event.
//   - Offline validation extends the Ed25519 artifact pattern to passes
//     (BFP1) with rotating validation key epochs and a signed, paginated
//     blocklist delta for conductor devices.
//   - Conductor store-and-forward batches dedupe durably per scan id,
//     preserve first-scan-wins for seat tickets, route conflicts to
//     REVIEW_REQUIRED and settle offline debits against per-device caps
//     (the advisory §9.5 liability rule: declines-after-sync are the
//     government's loss, so offline credit is never unbounded).
//
// All money is integer NGN minor units. There are no fabricated success
// paths: credits happen only on verified rail webhooks or ledger-confirmed
// agent cash events.
package fare

import (
	"errors"
	"time"
)

// TopicFare is the transactional-outbox topic for every BlueFare event.
const TopicFare = "ferries.fare.v1"

// Outbox event types produced by this package.
const (
	EventPassReserved  = "ferry.pass.reserved"
	EventPassPaid      = "ferry.pass.paid"
	EventPassIssued    = "ferry.pass.issued"
	EventPassSuspended = "ferry.pass.suspended"
	EventPassRevoked   = "ferry.pass.revoked"
	EventPassExpired   = "ferry.pass.expired"

	EventCapJourneyPriced   = "ferry.fare.cap_journey_priced"
	EventCapJourneyReversed = "ferry.fare.cap_journey_reversed"
	EventBestFareAdjusted   = "ferry.fare.best_fare_adjusted"

	EventFareAccountOpened    = "ferry.fare.account_opened"
	EventInstrumentRegistered = "ferry.fare.instrument_registered"
	EventTopUpInitiated       = "ferry.fare.topup_initiated"
	EventTopUpCredited        = "ferry.fare.topup_credited"
	EventTopUpFailed          = "ferry.fare.topup_failed"

	EventOfflineDebitSettled  = "ferry.fare.offline_debit_settled"
	EventOfflineDebitDeclined = "ferry.fare.offline_debit_declined"

	EventConductorBatchProcessed = "ferry.conductor.batch_processed"
	EventSettlementRunCompleted  = "ferry.fare.settlement_run_completed"

	EventAccountRefundRequested = "ferry.fare.account_refund_requested"
	EventAccountRefundApproved  = "ferry.fare.account_refund_approved"
	EventAccountRefundSettled   = "ferry.fare.account_refund_settled"
	EventAccountRefundRejected  = "ferry.fare.account_refund_rejected"
)

var (
	// ErrNotFound reports a missing record.
	ErrNotFound = errors.New("record not found")
	// ErrInvalidTransition rejects a state move outside the approved graph.
	ErrInvalidTransition = errors.New("fare state transition is not permitted")
	// ErrIdempotencyConflict reports a key replay against a different record.
	ErrIdempotencyConflict = errors.New("idempotency key is bound to a different record")
	// ErrValidationRejected rejects a credential that failed cryptographic or
	// policy validation; the PII-free reason travels with the result.
	ErrValidationRejected = errors.New("credential validation failed")
	// ErrDeviceNotProvisioned rejects offline-debit scans from a device with
	// no active offline cap row (fail closed: no unbounded offline credit).
	ErrDeviceNotProvisioned = errors.New("conductor device has no offline debit provisioning")
	// ErrWebhookSignature rejects rail webhooks whose HMAC does not verify.
	ErrWebhookSignature = errors.New("rail webhook signature is invalid")
	// ErrAccountNotActive rejects money movement on suspended/closed accounts.
	ErrAccountNotActive = errors.New("fare account is not active")
	// ErrMakerChecker rejects self-approval (four-eyes, fail closed).
	ErrMakerChecker = errors.New("maker and checker must be distinct")
)

// Pass kinds and their rolling validity durations (Venice-style 24h windows,
// documented: DAY = 24h, WEEK = 7 days, MONTH = 30 days from activation).
const (
	PassKindDay   = "DAY"
	PassKindWeek  = "WEEK"
	PassKindMonth = "MONTH"
)

// PassDuration maps a pass kind to its rolling validity duration.
func PassDuration(kind string) (time.Duration, error) {
	switch kind {
	case PassKindDay:
		return 24 * time.Hour, nil
	case PassKindWeek:
		return 7 * 24 * time.Hour, nil
	case PassKindMonth:
		return 30 * 24 * time.Hour, nil
	}
	return 0, errors.New("pass kind must be DAY, WEEK or MONTH")
}

// Pass lifecycle states.
const (
	PassStatusActive    = "ACTIVE"
	PassStatusSuspended = "SUSPENDED"
	PassStatusRevoked   = "REVOKED"
	PassStatusExpired   = "EXPIRED"
)

// Pass purchase saga states (mirror of the ticket saga).
const (
	PurchaseReserved = "RESERVED"
	PurchasePaid     = "PAID"
	PurchaseIssued   = "ISSUED"
	PurchaseExpired  = "EXPIRED"
	PurchaseVoid     = "VOID"
)

// Collection channels (mirror of ticketing channels plus BlueFare account).
const (
	ChannelDirect      = "DIRECT"
	ChannelAgentCashIn = "AGENT_CASH_IN"
	ChannelAccount     = "ACCOUNT"
)

// Top-up rails.
const (
	TopUpMojaloop    = "MOJALOOP"
	TopUpNIPTransfer = "NIP_TRANSFER"
	TopUpNQR         = "NQR"
	TopUpAgentCash   = "AGENT_CASH"
	TopUpUSSD        = "USSD"
)

// Top-up states: the honest pending-credit machine. Money is credited only
// on a verified rail webhook (or, for AGENT_CASH, the ledger-confirmed agent
// float event). Nothing self-reports success.
const (
	TopUpPending  = "PENDING"
	TopUpCredited = "CREDITED"
	TopUpFailed   = "FAILED"
	TopUpExpired  = "EXPIRED"
)

// Pricing classes recorded on every priced journey.
const (
	PricingStandard   = "STANDARD"
	PricingConcession = "CONCESSION"
	PricingTransfer   = "TRANSFER"
	PricingCapped     = "CAPPED"
	PricingZeroCap    = "ZERO_CAP"
)

// Concession classes (encoded rules with eligibility references, never
// discretion).
const (
	ConcessionStandard = "STANDARD"
	ConcessionStudent  = "STUDENT"
	ConcessionElderly  = "ELDERLY"
	ConcessionPWD      = "PWD"
)

// Conductor scan results.
const (
	ScanAdmitted       = "ADMITTED"
	ScanDenied         = "DENIED"
	ScanDuplicate      = "DUPLICATE"
	ScanReviewRequired = "REVIEW_REQUIRED"
)

// Offline debit settlement states.
const (
	DebitSettled  = "SETTLED"
	DebitDeclined = "DECLINED"
	DebitReview   = "REVIEW"
)

// CapProduct / pass scope types.
const (
	ScopeTypeRoute   = "ROUTE"
	ScopeTypeZone    = "ZONE"
	ScopeTypeNetwork = "NETWORK"
)

// PassProduct is one sellable period-pass product.
type PassProduct struct {
	ProductID      string
	Kind           string
	ScopeType      string
	ScopeRef       string
	PriceNGNMinor  int64
	OperatorID     string // "" = ministry/platform product
	Active         bool
	CreatedAt      time.Time
}

// Pass is one issued period pass.
type Pass struct {
	PassID      string
	ProductID   string
	OwnerDigest string
	ValidFrom   time.Time
	ValidTo     time.Time
	Status      string
	PurchaseID  string
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PassPurchase is one pass-purchase saga record.
type PassPurchase struct {
	PurchaseID         string
	ProductID          string
	PassID             string
	OwnerDigest        string
	PriceNGNMinor      int64
	Channel            string
	AgentID            string
	AccountID          string
	State              string
	Version            int64
	LedgerReserveID    string
	LedgerPostID       string
	PurchaserPrincipal string
	CorrelationID      string
	IdempotencyKey     string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// CapJourney is the pricing decision record for one journey.
type CapJourney struct {
	JourneyID          string
	SubjectRef         string
	AccountID          string
	TripID             string
	RouteReference     string
	OperatorID         string
	StandardFareMinor  int64
	ChargedMinor       int64
	PricingClass       string
	ConcessionClass    string
	TicketID           string
	Reversed           bool
	CreatedAt          time.Time
}

// FareAccount is one BlueFare account (value lives on the ledger; the cached
// balance is a read-model for offline floors and UI only).
type FareAccount struct {
	AccountID           string
	OwnerRef            string
	OwnerDigest         string
	Status              string
	ConcessionClass     string
	ConcessionReference string
	AutoloadEnabled     bool
	AutoloadThreshold   *int64
	AutoloadAmount      *int64
	LedgerAccountID     string
	CachedBalanceMinor  int64
	BalanceAsOf         *time.Time
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Instrument is one pointer at a fare account (phone QR today; NFC tokens
// are a later wave but the model carries them).
type Instrument struct {
	InstrumentID string
	AccountID    string
	Kind         string
	TokenRef     string
	Status       string
	PublicKeyHex string // NFC_TAP enrollment key (Ed25519, hex)
	TapCounter   uint64 // monotonic anti-replay counter
	CreatedAt    time.Time
}

// TopUp is one account funding record.
type TopUp struct {
	TopUpID          string
	AccountID        string
	Channel          string
	AmountNGNMinor   int64
	State            string
	Reference        string
	ExternalRef      string
	AgentID          string
	IdempotencyKey   string
	LedgerTransferID string
	FailureReason    string
	Version          int64
	CreatedAt        time.Time
	CreditedAt       *time.Time
}

// Account refund saga states (PRA-136): maker requests, a DISTINCT checker
// approves or rejects, settlement moves value from operator revenue to the
// fare account exactly once (deterministic ledger transfer ID).
const (
	RefundRequested = "REQUESTED"
	RefundApproved  = "APPROVED"
	RefundSettled   = "SETTLED"
	RefundRejected  = "REJECTED"
)

// AccountRefund is one refund-to-account saga record.
type AccountRefund struct {
	RefundID         string     `json:"refundId"`
	AccountID        string     `json:"accountId"`
	AmountMinor      int64      `json:"amountNgnMinor"`
	Reason           string     `json:"reason"`
	IdempotencyKey   string     `json:"idempotencyKey"`
	State            string     `json:"state"`
	Maker            string     `json:"maker"`
	Checker          string     `json:"checker,omitempty"`
	LedgerTransferID string     `json:"ledgerTransferId,omitempty"`
	Version          int64      `json:"version"`
	CorrelationID    string     `json:"correlationId"`
	CreatedAt        time.Time  `json:"createdAt"`
	DecidedAt        *time.Time `json:"decidedAt,omitempty"`
	SettledAt        *time.Time `json:"settledAt,omitempty"`
}

// ValidationDecision is the ADMIT/DENY result of pass validation. Reason is
// a stable PII-free code; the response never carries owner data.
type ValidationDecision struct {
	Admit    bool   `json:"admit"`
	Reason   string `json:"reason,omitempty"`
	PassID   string `json:"passId,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ScopeRef string `json:"scopeRef,omitempty"`
	ValidTo  string `json:"validTo,omitempty"`
	Epoch    uint32 `json:"epoch,omitempty"`
}
