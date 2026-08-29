package fare

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// AccountService manages BlueFare accounts, instruments and top-ups.
// Account-based tenet: value lives on the ledger account; instruments are
// pointers. Credits happen only on verified rail webhooks or the
// ledger-confirmed agent cash path — never on self-reported success.
type AccountService struct {
	store     *PostgresStore
	accounts  AccountLedger
	salt      string
	webhookHMAC string
	now       func() time.Time
}

// NewAccountService fails closed on any missing dependency.
func NewAccountService(store *PostgresStore, accounts AccountLedger, manifestSalt, webhookHMACSecret string) (*AccountService, error) {
	if store == nil {
		return nil, errors.New("fare store is required")
	}
	if accounts == nil {
		return nil, errors.New("account ledger is required (fail-closed)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	if len(webhookHMACSecret) < 16 {
		return nil, errors.New("rail webhook HMAC secret of at least 16 characters is required (fail-closed)")
	}
	return &AccountService{store: store, accounts: accounts, salt: manifestSalt, webhookHMAC: webhookHMACSecret,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// OpenAccount provisions the ledger account (no-negative constraint) and
// persists the metadata atomically with the audit event. A non-STANDARD
// concession class requires an eligibility evidence reference (encoded
// rules, never discretion).
func (service *AccountService) OpenAccount(ctx context.Context, ownerRef, concessionClass, concessionReference, principal, correlationID string) (FareAccount, error) {
	if strings.TrimSpace(ownerRef) == "" || len(ownerRef) > 256 {
		return FareAccount{}, errors.New("owner reference is required")
	}
	switch concessionClass {
	case ConcessionStandard:
	case ConcessionStudent, ConcessionElderly, ConcessionPWD:
		if strings.TrimSpace(concessionReference) == "" {
			return FareAccount{}, errors.New("concession classes require an eligibility reference")
		}
	default:
		return FareAccount{}, fmt.Errorf("concession class %q is not supported", concessionClass)
	}
	digest, err := ticketing.PassengerDigest(service.salt, ownerRef)
	if err != nil {
		return FareAccount{}, err
	}
	account := FareAccount{
		AccountID:           uuid.NewString(),
		OwnerRef:            ownerRef,
		OwnerDigest:         digest,
		Status:              "ACTIVE",
		ConcessionClass:     concessionClass,
		ConcessionReference: concessionReference,
		LedgerAccountID:     "", // set below
	}
	ledgerID := ledger.FareAccountID(account.AccountID)
	if err := service.accounts.EnsureAccount(ledgerID, true); err != nil {
		return FareAccount{}, fmt.Errorf("provision ledger account: %w", err)
	}
	account.LedgerAccountID = ledgerID.String()
	if err := service.store.OpenFareAccount(ctx, account, service.event(EventFareAccountOpened, account.AccountID, correlationID, map[string]any{
		"account_id":       account.AccountID,
		"owner_digest":     account.OwnerDigest,
		"concession_class": account.ConcessionClass,
		"principal_id":     principal,
	})); err != nil {
		return FareAccount{}, err
	}
	return account, nil
}

// RegisterInstrument points one instrument token at an account.
func (service *AccountService) RegisterInstrument(ctx context.Context, accountID, kind, tokenRef, principal, correlationID string) (Instrument, error) {
	if _, err := service.store.GetFareAccount(ctx, accountID); err != nil {
		return Instrument{}, err
	}
	switch kind {
	case "PHONE_QR", "NFC_CARD", "USSD_ALIAS":
	default:
		return Instrument{}, fmt.Errorf("instrument kind %q is not supported", kind)
	}
	if strings.TrimSpace(tokenRef) == "" || len(tokenRef) > 256 {
		return Instrument{}, errors.New("instrument token reference is required")
	}
	instrument := Instrument{
		InstrumentID: uuid.NewString(),
		AccountID:    accountID,
		Kind:         kind,
		TokenRef:     tokenRef,
		Status:       "ACTIVE",
	}
	if err := service.store.RegisterInstrument(ctx, instrument, service.event(EventInstrumentRegistered, instrument.InstrumentID, correlationID, map[string]any{
		"instrument_id": instrument.InstrumentID,
		"account_id":    accountID,
		"kind":          kind,
		"principal_id":  principal,
	})); err != nil {
		return Instrument{}, err
	}
	return instrument, nil
}

// TopUpRequest carries one account funding request.
type TopUpRequest struct {
	AccountID      string
	Channel        string
	AmountNGNMinor int64
	AgentID        string
	IdempotencyKey string
	CorrelationID  string
	Principal      string
}

// TopUp funds an account. AGENT_CASH credits immediately through the agent
// float ledger path (cash in hand, ledger-confirmed). Every rail channel
// (MOJALOOP, NIP_TRANSFER, NQR, USSD) enters the honest PENDING state and
// credits only on a verified rail webhook — the sandbox never fakes credits.
// Replay of the same idempotency key returns the original top-up.
func (service *AccountService) TopUp(ctx context.Context, request TopUpRequest) (TopUp, error) {
	if strings.TrimSpace(request.AccountID) == "" || request.AmountNGNMinor <= 0 {
		return TopUp{}, errors.New("account id and positive amount are required")
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 128 {
		return TopUp{}, errors.New("idempotency key is required")
	}
	account, err := service.store.GetFareAccount(ctx, request.AccountID)
	if err != nil {
		return TopUp{}, err
	}
	if account.Status != "ACTIVE" {
		return TopUp{}, ErrAccountNotActive
	}
	if existing, err := service.store.GetTopUpByIdempotency(ctx, request.IdempotencyKey); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return TopUp{}, fmt.Errorf("resolve idempotency key: %w", err)
	}
	topup := TopUp{
		TopUpID:        uuid.NewString(),
		AccountID:      request.AccountID,
		Channel:        request.Channel,
		AmountNGNMinor: request.AmountNGNMinor,
		AgentID:        request.AgentID,
		IdempotencyKey: request.IdempotencyKey,
	}
	topup.Reference = topupReference(topup.Channel, topup.TopUpID)
	switch request.Channel {
	case TopUpAgentCash:
		if strings.TrimSpace(request.AgentID) == "" {
			return TopUp{}, errors.New("agent_id is required for agent cash top-ups")
		}
		// Ledger first: the agent float debit is the money movement; the PG
		// record follows (same saga discipline as ticket cash-in).
		transferID, err := service.accounts.CreditAccount(ctx, topup.TopUpID, account.LedgerAccountID, topup.AmountNGNMinor, ledger.FundingAgentFloat)
		if err != nil {
			return TopUp{}, fmt.Errorf("credit agent cash top-up on ledger: %w", err)
		}
		topup.State = TopUpCredited
		topup.LedgerTransferID = transferID
		now := service.now()
		topup.CreditedAt = &now
		if err := service.store.InsertTopUp(ctx, topup, service.event(EventTopUpCredited, topup.TopUpID, request.CorrelationID, map[string]any{
			"topup_id":           topup.TopUpID,
			"account_id":         topup.AccountID,
			"channel":            topup.Channel,
			"agent_id":           topup.AgentID,
			"amount_ngn_minor":   topup.AmountNGNMinor,
			"ledger_transfer_id": transferID,
			"principal_id":       request.Principal,
			"state":              TopUpCredited,
		})); err != nil {
			return TopUp{}, err
		}
		return topup, nil
	case TopUpMojaloop, TopUpNIPTransfer, TopUpNQR, TopUpUSSD:
		// Honest pending-credit: the rail must confirm. NIP uses the unique
		// reference as the transfer narration; NQR encodes it in the EMV
		// payload; Mojaloop binds it to the quote; USSD reads it to the
		// session. Cross-service rail wiring is a later wave — this service
		// owns the state machine and the verification boundary.
		topup.State = TopUpPending
		if err := service.store.InsertTopUp(ctx, topup, service.event(EventTopUpInitiated, topup.TopUpID, request.CorrelationID, map[string]any{
			"topup_id":         topup.TopUpID,
			"account_id":       topup.AccountID,
			"channel":          topup.Channel,
			"reference":        topup.Reference,
			"amount_ngn_minor": topup.AmountNGNMinor,
			"principal_id":     request.Principal,
			"state":            TopUpPending,
		})); err != nil {
			return TopUp{}, err
		}
		return topup, nil
	}
	return TopUp{}, fmt.Errorf("top-up channel %q is not supported", request.Channel)
}

// topupReference derives the unique payer-facing transfer reference.
func topupReference(channel, topupID string) string {
	prefix := map[string]string{
		TopUpMojaloop:    "BFM",
		TopUpNIPTransfer: "BFN",
		TopUpNQR:         "BFQ",
		TopUpUSSD:        "BFU",
		TopUpAgentCash:   "BFA",
	}[channel]
	compact := strings.ReplaceAll(topupID, "-", "")
	return fmt.Sprintf("%s-%s", prefix, strings.ToUpper(compact[:16]))
}

// RailWebhook is the verified rail callback payload.
type RailWebhook struct {
	Reference   string `json:"reference"`
	ExternalRef string `json:"externalRef"`
	AmountMinor int64  `json:"amountNgnMinor"`
	Status      string `json:"status"` // SUCCESS | FAILED
}

// VerifyWebhookSignature checks the HMAC-SHA256 over the raw request body
// (hex in the X-Rail-Signature header). Fail closed on any mismatch.
func (service *AccountService) VerifyWebhookSignature(rawBody []byte, signatureHex string) error {
	signature, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil || len(signature) != sha256.Size {
		return ErrWebhookSignature
	}
	mac := hmac.New(sha256.New, []byte(service.webhookHMAC))
	mac.Write(rawBody)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ErrWebhookSignature
	}
	return nil
}

// HandleRailWebhook applies one verified rail callback. Credits are
// idempotent per external_ref and per top-up state: replays return the
// current state and never double-credit.
func (service *AccountService) HandleRailWebhook(ctx context.Context, webhook RailWebhook, correlationID string) (TopUp, error) {
	if strings.TrimSpace(webhook.Reference) == "" || strings.TrimSpace(webhook.ExternalRef) == "" {
		return TopUp{}, errors.New("webhook reference and external reference are required")
	}
	topup, err := service.store.GetTopUpByReference(ctx, webhook.Reference)
	if err != nil {
		return TopUp{}, fmt.Errorf("resolve top-up reference: %w", err)
	}
	if topup.State == TopUpCredited || topup.State == TopUpFailed {
		return topup, nil // replay: terminal state is authoritative
	}
	if webhook.AmountMinor != topup.AmountNGNMinor {
		return TopUp{}, fmt.Errorf("webhook amount %d does not match top-up amount %d", webhook.AmountMinor, topup.AmountNGNMinor)
	}
	switch webhook.Status {
	case "SUCCESS":
		account, err := service.store.GetFareAccount(ctx, topup.AccountID)
		if err != nil {
			return TopUp{}, err
		}
		transferID, err := service.accounts.CreditAccount(ctx, topup.TopUpID, account.LedgerAccountID, topup.AmountNGNMinor, ledger.FundingPassengerClearing)
		if err != nil {
			return TopUp{}, fmt.Errorf("credit top-up on ledger: %w", err)
		}
		if _, err := service.store.CreditTopUp(ctx, topup, webhook.ExternalRef, transferID, service.event(EventTopUpCredited, topup.TopUpID, correlationID, map[string]any{
			"topup_id":           topup.TopUpID,
			"account_id":         topup.AccountID,
			"channel":            topup.Channel,
			"reference":          topup.Reference,
			"external_ref":       webhook.ExternalRef,
			"amount_ngn_minor":   topup.AmountNGNMinor,
			"ledger_transfer_id": transferID,
			"state":              TopUpCredited,
		})); err != nil {
			return TopUp{}, err
		}
	case "FAILED":
		if err := service.store.FailTopUp(ctx, topup.TopUpID, webhook.ExternalRef, "rail reported failure", service.event(EventTopUpFailed, topup.TopUpID, correlationID, map[string]any{
			"topup_id":     topup.TopUpID,
			"account_id":   topup.AccountID,
			"channel":      topup.Channel,
			"reference":    topup.Reference,
			"external_ref": webhook.ExternalRef,
			"state":        TopUpFailed,
		})); err != nil {
			return TopUp{}, err
		}
	default:
		return TopUp{}, fmt.Errorf("webhook status %q is not supported", webhook.Status)
	}
	return service.store.GetTopUp(ctx, topup.TopUpID)
}

// AccountView is the account plus its reconciliation read-model: the cached
// balance versus the flow-computed balance (credited top-ups minus charged
// journeys and settled offline debits). Drift here is a reconciliation
// signal; the TigerBeetle balance is authoritative.
type AccountView struct {
	Account          FareAccount `json:"account"`
	CreditedMinor    int64       `json:"creditedNgnMinor"`
	JourneyMinor     int64       `json:"journeyChargesNgnMinor"`
	OfflineDebitMinor int64      `json:"offlineDebitsNgnMinor"`
	FlowBalanceMinor int64       `json:"flowBalanceNgnMinor"`
	CachedBalanceMinor int64     `json:"cachedBalanceNgnMinor"`
	CacheDriftMinor  int64       `json:"cacheDriftNgnMinor"`
}

// GetAccountView loads one account with its reconciliation view.
func (service *AccountService) GetAccountView(ctx context.Context, accountID string) (AccountView, error) {
	account, err := service.store.GetFareAccount(ctx, accountID)
	if err != nil {
		return AccountView{}, err
	}
	flows, err := service.store.ComputeAccountFlows(ctx, accountID)
	if err != nil {
		return AccountView{}, err
	}
	flowBalance := flows.CreditedMinor - flows.JourneyMinor - flows.OfflineDebitMinor
	return AccountView{
		Account:            account,
		CreditedMinor:      flows.CreditedMinor,
		JourneyMinor:       flows.JourneyMinor,
		OfflineDebitMinor:  flows.OfflineDebitMinor,
		FlowBalanceMinor:   flowBalance,
		CachedBalanceMinor: account.CachedBalanceMinor,
		CacheDriftMinor:    account.CachedBalanceMinor - flowBalance,
	}, nil
}

func (service *AccountService) event(eventType, subjectID, correlationID string, payload map[string]any) ticketing.Event {
	if correlationID == "" {
		correlationID = uuid.NewString()
	}
	return ticketing.Event{
		EventID:       uuid.NewString(),
		Topic:         TopicFare,
		SubjectID:     subjectID,
		EventType:     eventType,
		CorrelationID: correlationID,
		Payload:       payload,
	}
}
