// Package ledger is the TigerBeetle boundary for ferry ticketing. Fares move
// with the two-phase reserve/post pattern: a pending transfer is created at
// reservation and posted on payment (or voided on abandonment). The client is
// behind an interface and the service is fail-closed when unconfigured.
package ledger

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
)

// Client is the subset of the TigerBeetle client the service needs.
type Client interface {
	CreateAccounts([]tigerbeetle.Account) ([]tigerbeetle.CreateAccountResult, error)
	CreateTransfers([]tigerbeetle.Transfer) ([]tigerbeetle.CreateTransferResult, error)
	LookupTransfers([]tigerbeetle.Uint128) ([]tigerbeetle.Transfer, error)
}

// Topology is the approved account/ledger layout. All values are operator
// configuration; there are no defaults.
type Topology struct {
	Ledger                   uint32
	Code                     uint16
	PassengerClearingAccount tigerbeetle.Uint128
	OperatorRevenueAccount   tigerbeetle.Uint128
	AgentFloatAccount        tigerbeetle.Uint128
	// MinistrySubsidyAccount funds encoded subsidy (concessions, ministry
	// top-ups); PlatformFeeAccount receives the platform share of operator
	// settlements. Both are operator configuration, never defaulted.
	MinistrySubsidyAccount tigerbeetle.Uint128
	PlatformFeeAccount     tigerbeetle.Uint128
	PendingTimeoutSeconds  uint32
}

// Validate fails closed on any gap in the topology.
func (topology Topology) Validate() error {
	zero := tigerbeetle.Uint128{}
	if topology.Ledger == 0 || topology.Code == 0 || topology.PendingTimeoutSeconds == 0 {
		return errors.New("ledger, code and pending timeout must be non-zero")
	}
	if topology.PassengerClearingAccount == zero || topology.OperatorRevenueAccount == zero || topology.AgentFloatAccount == zero {
		return errors.New("clearing, revenue and agent float accounts must be non-zero")
	}
	if topology.MinistrySubsidyAccount == zero || topology.PlatformFeeAccount == zero {
		return errors.New("ministry subsidy and platform fee accounts must be non-zero")
	}
	accounts := []tigerbeetle.Uint128{
		topology.PassengerClearingAccount, topology.OperatorRevenueAccount,
		topology.AgentFloatAccount, topology.MinistrySubsidyAccount, topology.PlatformFeeAccount,
	}
	for i, left := range accounts {
		for _, right := range accounts[i+1:] {
			if left == right {
				return errors.New("ledger accounts must be distinct")
			}
		}
	}
	return nil
}

// Service implements ticketing.Ledger against TigerBeetle.
type Service struct {
	client   Client
	topology Topology
}

// New fails closed on a nil client or invalid topology.
func New(client Client, topology Topology) (*Service, error) {
	if client == nil {
		return nil, errors.New("TigerBeetle client is required")
	}
	if err := topology.Validate(); err != nil {
		return nil, err
	}
	return &Service{client: client, topology: topology}, nil
}

// EnsureAccounts creates the topology accounts (idempotent).
func (service *Service) EnsureAccounts() error {
	for _, id := range []tigerbeetle.Uint128{
		service.topology.PassengerClearingAccount,
		service.topology.OperatorRevenueAccount,
		service.topology.AgentFloatAccount,
		service.topology.MinistrySubsidyAccount,
		service.topology.PlatformFeeAccount,
	} {
		results, err := service.client.CreateAccounts([]tigerbeetle.Account{{
			ID:     id,
			Ledger: service.topology.Ledger,
			Code:   service.topology.Code,
		}})
		if err != nil {
			return fmt.Errorf("create TigerBeetle account: %w", err)
		}
		if len(results) == 1 &&
			results[0].Status != tigerbeetle.AccountCreated &&
			results[0].Status != tigerbeetle.AccountExists {
			return fmt.Errorf("create TigerBeetle account returned status %v", results[0].Status)
		}
	}
	return nil
}

// debitAccount resolves the fare source: the agent float account for cash-in
// purchases, the passenger clearing account otherwise.
func (service *Service) debitAccount(channel ticketing.Channel) (tigerbeetle.Uint128, error) {
	switch channel {
	case ticketing.ChannelAgentCashIn:
		return service.topology.AgentFloatAccount, nil
	case ticketing.ChannelDirect:
		return service.topology.PassengerClearingAccount, nil
	}
	return tigerbeetle.Uint128{}, fmt.Errorf("channel %q has no ledger debit account", channel)
}

// Reserve implements ticketing.Ledger: pending two-phase transfer.
func (service *Service) Reserve(_ context.Context, ticketID string, channel ticketing.Channel, amountNGNMinor int64) (string, error) {
	if ticketID == "" || amountNGNMinor <= 0 {
		return "", errors.New("ticket id and positive amount are required")
	}
	debit, err := service.debitAccount(channel)
	if err != nil {
		return "", err
	}
	transferID := transferIDFor(ticketID, "reserve")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              transferID,
		DebitAccountID:  debit,
		CreditAccountID: service.topology.OperatorRevenueAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Timeout:         service.topology.PendingTimeoutSeconds,
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
		Flags:           tigerbeetle.TransferFlags{Pending: true}.ToUint16(),
	}); err != nil {
		return "", fmt.Errorf("reserve fare: %w", err)
	}
	return transferID.String(), nil
}

// Post implements ticketing.Ledger: settle the pending reserve.
func (service *Service) Post(_ context.Context, reserveTransferID string) (string, error) {
	pendingID, err := ParseID(reserveTransferID)
	if err != nil {
		return "", err
	}
	postID := transferIDFor(reserveTransferID, "post")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:        postID,
		PendingID: pendingID,
		Ledger:    service.topology.Ledger,
		Code:      service.topology.Code,
		Flags:     tigerbeetle.TransferFlags{PostPendingTransfer: true}.ToUint16(),
	}); err != nil {
		return "", fmt.Errorf("post fare: %w", err)
	}
	return postID.String(), nil
}

// Void implements ticketing.Ledger: release the pending reserve.
func (service *Service) Void(_ context.Context, reserveTransferID string) error {
	pendingID, err := ParseID(reserveTransferID)
	if err != nil {
		return err
	}
	return service.createTransfer(tigerbeetle.Transfer{
		ID:        transferIDFor(reserveTransferID, "void"),
		PendingID: pendingID,
		Ledger:    service.topology.Ledger,
		Code:      service.topology.Code,
		Flags:     tigerbeetle.TransferFlags{VoidPendingTransfer: true}.ToUint16(),
	})
}

// ResolveReserve implements ticketing.Ledger: reconcile one reserve transfer
// against the cluster. The post/void transfer IDs are deterministic, so their
// presence is authoritative: an existing post transfer means the fare
// settled; an existing void transfer means it was released. A reserve that
// still exists without its pending flag was auto-voided by the pending
// timeout (TigerBeetle resolves expired pending transfers without creating a
// companion void transfer).
func (service *Service) ResolveReserve(_ context.Context, reserveTransferID string) (ticketing.ReserveResolution, error) {
	pendingID, err := ParseID(reserveTransferID)
	if err != nil {
		return ticketing.ReserveResolution{}, err
	}
	postID := transferIDFor(reserveTransferID, "post")
	voidID := transferIDFor(reserveTransferID, "void")
	transfers, err := service.client.LookupTransfers([]tigerbeetle.Uint128{pendingID, postID, voidID})
	if err != nil {
		return ticketing.ReserveResolution{}, fmt.Errorf("lookup reserve transfers: %w", err)
	}
	byID := make(map[tigerbeetle.Uint128]tigerbeetle.Transfer, len(transfers))
	for _, transfer := range transfers {
		byID[transfer.ID] = transfer
	}
	if _, posted := byID[postID]; posted {
		return ticketing.ReserveResolution{Status: ticketing.ReserveStatusPosted, PostTransferID: postID.String()}, nil
	}
	if _, voided := byID[voidID]; voided {
		return ticketing.ReserveResolution{Status: ticketing.ReserveStatusReleased}, nil
	}
	pending, exists := byID[pendingID]
	if !exists {
		return ticketing.ReserveResolution{Status: ticketing.ReserveStatusUnknown}, nil
	}
	if pending.TransferFlags().Pending {
		return ticketing.ReserveResolution{Status: ticketing.ReserveStatusPending}, nil
	}
	// The pending transfer exists but is no longer pending and no post/void
	// companion exists: the pending timeout auto-voided it.
	return ticketing.ReserveResolution{Status: ticketing.ReserveStatusReleased}, nil
}

// Refund implements ticketing.Ledger: move the fare back from operator
// revenue to the passenger clearing account.
func (service *Service) Refund(_ context.Context, ticketID string, amountNGNMinor int64) (string, error) {
	if ticketID == "" || amountNGNMinor <= 0 {
		return "", errors.New("ticket id and positive amount are required")
	}
	refundID := transferIDFor(ticketID, "refund")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              refundID,
		DebitAccountID:  service.topology.OperatorRevenueAccount,
		CreditAccountID: service.topology.PassengerClearingAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
	}); err != nil {
		return "", fmt.Errorf("refund fare: %w", err)
	}
	return refundID.String(), nil
}

func (service *Service) createTransfer(transfer tigerbeetle.Transfer) error {
	results, err := service.client.CreateTransfers([]tigerbeetle.Transfer{transfer})
	if err != nil {
		return fmt.Errorf("create TigerBeetle transfer: %w", err)
	}
	if len(results) > 1 {
		return fmt.Errorf("create TigerBeetle transfer returned %d results, want at most 1", len(results))
	}
	// TigerBeetle deduplicates re-submitted transfer IDs; an empty result set
	// means the deterministic ID already exists (idempotent replay).
	if len(results) == 1 && results[0].Status != tigerbeetle.TransferCreated && results[0].Status != tigerbeetle.TransferExists {
		return fmt.Errorf("create TigerBeetle transfer returned status %v", results[0].Status)
	}
	return nil
}

// transferIDFor derives a deterministic, non-zero uint128 transfer ID from a
// ticket/transfer reference and a phase tag, so idempotent replays map to the
// same TigerBeetle transfer ID (deduplicated cluster-side).
func transferIDFor(reference, phase string) tigerbeetle.Uint128 {
	if reference == "" {
		return tigerbeetle.Uint128{}
	}
	hash := sha256.Sum256([]byte("ferry-ticketing:" + reference + ":" + phase))
	var bytes [16]byte
	copy(bytes[:], hash[:16])
	id := tigerbeetle.BytesToUint128(bytes)
	if id == (tigerbeetle.Uint128{}) {
		// Astronomically impossible for SHA-256, but fail closed anyway.
		bytes[15] = 1
		id = tigerbeetle.BytesToUint128(bytes)
	}
	return id
}

// ParseID parses a transfer ID, failing closed on malformed or zero values.
func ParseID(value string) (tigerbeetle.Uint128, error) {
	if value == "" {
		return tigerbeetle.Uint128{}, errors.New("transfer id is required")
	}
	id, err := tigerbeetle.HexStringToUint128(value)
	if err != nil {
		return tigerbeetle.Uint128{}, fmt.Errorf("parse transfer id: %w", err)
	}
	if id == (tigerbeetle.Uint128{}) {
		return tigerbeetle.Uint128{}, errors.New("transfer id must be non-zero")
	}
	return id, nil
}
