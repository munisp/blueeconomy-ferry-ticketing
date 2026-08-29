package ledger

import (
	"context"
	"errors"
	"fmt"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
)

// BlueFare account-based extensions (Advisory §4.2): value lives on
// TigerBeetle accounts; instruments are pointers. Fare accounts carry
// DEBITS_MUST_NOT_EXCEED_CREDITS so a negative rider balance is impossible
// by construction — the same flag that powers seat-inventory non-oversell.

// FundingSource identifies where top-up value enters the ledger from.
type FundingSource string

const (
	// FundingPassengerClearing is the rail-settled entry (Mojaloop / NIP /
	// NQR / USSD top-ups settle into passenger clearing first).
	FundingPassengerClearing FundingSource = "PASSENGER_CLEARING"
	// FundingAgentFloat is cash collected by an accredited agent.
	FundingAgentFloat FundingSource = "AGENT_FLOAT"
	// FundingMinistrySubsidy is a subsidy top-up from the ministry account.
	FundingMinistrySubsidy FundingSource = "MINISTRY_SUBSIDY"
)

// FareAccountID derives the deterministic TigerBeetle account for one
// BlueFare account (stored on fare_accounts.ledger_account_id).
func FareAccountID(accountID string) tigerbeetle.Uint128 {
	return transferIDFor("fare-account:"+accountID, "account")
}

// OperatorWalletID derives the deterministic operator settlement wallet.
func OperatorWalletID(operatorID string) tigerbeetle.Uint128 {
	return transferIDFor("operator-wallet:"+operatorID, "account")
}

// EnsureAccount creates one account (idempotent), with the no-negative
// balance constraint when constrained is true (fare accounts, wallets).
func (service *Service) EnsureAccount(id tigerbeetle.Uint128, constrained bool) error {
	if id == (tigerbeetle.Uint128{}) {
		return errors.New("account id must be non-zero")
	}
	account := tigerbeetle.Account{
		ID:     id,
		Ledger: service.topology.Ledger,
		Code:   service.topology.Code,
	}
	if constrained {
		account.Flags = tigerbeetle.AccountFlags{DebitsMustNotExceedCredits: true}.ToUint16()
	}
	results, err := service.client.CreateAccounts([]tigerbeetle.Account{account})
	if err != nil {
		return fmt.Errorf("create TigerBeetle account: %w", err)
	}
	if len(results) == 1 &&
		results[0].Status != tigerbeetle.AccountCreated &&
		results[0].Status != tigerbeetle.AccountExists {
		return fmt.Errorf("create TigerBeetle account returned status %v", results[0].Status)
	}
	return nil
}

func (service *Service) fundingAccount(source FundingSource) (tigerbeetle.Uint128, error) {
	switch source {
	case FundingPassengerClearing:
		return service.topology.PassengerClearingAccount, nil
	case FundingAgentFloat:
		return service.topology.AgentFloatAccount, nil
	case FundingMinistrySubsidy:
		return service.topology.MinistrySubsidyAccount, nil
	}
	return tigerbeetle.Uint128{}, fmt.Errorf("funding source %q has no ledger account", source)
}

// ReserveFromAccount creates the two-phase pending transfer debiting one
// BlueFare fare account (boarding hold) toward operator revenue. Post/Void
// of the returned reserve ID reuse the existing ticketing.Ledger methods.
func (service *Service) ReserveFromAccount(_ context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error) {
	if reference == "" || amountNGNMinor <= 0 {
		return "", errors.New("reference and positive amount are required")
	}
	fareAccount, err := ParseID(fareAccountIDHex)
	if err != nil {
		return "", err
	}
	transferID := transferIDFor(reference, "reserve")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              transferID,
		DebitAccountID:  fareAccount,
		CreditAccountID: service.topology.OperatorRevenueAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Timeout:         service.topology.PendingTimeoutSeconds,
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
		Flags:           tigerbeetle.TransferFlags{Pending: true}.ToUint16(),
	}); err != nil {
		return "", fmt.Errorf("reserve fare from account: %w", err)
	}
	return transferID.String(), nil
}

// CreditAccount settles a verified top-up into a fare account (single-phase;
// the rail already moved the money into the funding account).
func (service *Service) CreditAccount(_ context.Context, reference, fareAccountIDHex string, amountNGNMinor int64, source FundingSource) (string, error) {
	if reference == "" || amountNGNMinor <= 0 {
		return "", errors.New("reference and positive amount are required")
	}
	fareAccount, err := ParseID(fareAccountIDHex)
	if err != nil {
		return "", err
	}
	funding, err := service.fundingAccount(source)
	if err != nil {
		return "", err
	}
	creditID := transferIDFor(reference, "credit")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              creditID,
		DebitAccountID:  funding,
		CreditAccountID: fareAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
	}); err != nil {
		return "", fmt.Errorf("credit fare account: %w", err)
	}
	return creditID.String(), nil
}

// DebitAccount settles one offline debit (or direct account charge) from a
// fare account to operator revenue. A fare account carries
// DEBITS_MUST_NOT_EXCEED_CREDITS, so an insufficient balance is rejected by
// the cluster — the decline-after-sync case of the advisory's liability rule.
func (service *Service) DebitAccount(_ context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error) {
	if reference == "" || amountNGNMinor <= 0 {
		return "", errors.New("reference and positive amount are required")
	}
	fareAccount, err := ParseID(fareAccountIDHex)
	if err != nil {
		return "", err
	}
	debitID := transferIDFor(reference, "debit")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              debitID,
		DebitAccountID:  fareAccount,
		CreditAccountID: service.topology.OperatorRevenueAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
	}); err != nil {
		return "", fmt.Errorf("debit fare account: %w", err)
	}
	return debitID.String(), nil
}

// RefundToAccount moves value back from operator revenue to a fare account
// (account-ticket refunds, best-fare adjustments).
func (service *Service) RefundToAccount(_ context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error) {
	if reference == "" || amountNGNMinor <= 0 {
		return "", errors.New("reference and positive amount are required")
	}
	fareAccount, err := ParseID(fareAccountIDHex)
	if err != nil {
		return "", err
	}
	refundID := transferIDFor(reference, "refund-account")
	if err := service.createTransfer(tigerbeetle.Transfer{
		ID:              refundID,
		DebitAccountID:  service.topology.OperatorRevenueAccount,
		CreditAccountID: fareAccount,
		Amount:          tigerbeetle.ToUint128(uint64(amountNGNMinor)),
		Ledger:          service.topology.Ledger,
		Code:            service.topology.Code,
	}); err != nil {
		return "", fmt.Errorf("refund to fare account: %w", err)
	}
	return refundID.String(), nil
}

// LinkedSettlement executes one operator settlement as an atomic linked
// chain (Advisory §4.2: linked transfers = no partial settlement states):
// operator revenue -> operator wallet (share), then -> platform fee account
// (remainder), all-or-nothing.
func (service *Service) LinkedSettlement(_ context.Context, runID, operatorWalletIDHex string, operatorShareMinor, platformShareMinor int64) ([]string, error) {
	if runID == "" || operatorShareMinor < 0 || platformShareMinor < 0 || operatorShareMinor+platformShareMinor <= 0 {
		return nil, errors.New("run id and a positive total settlement amount are required")
	}
	wallet, err := ParseID(operatorWalletIDHex)
	if err != nil {
		return nil, err
	}
	if service.topology.PlatformFeeAccount == (tigerbeetle.Uint128{}) {
		return nil, errors.New("platform fee account is not configured (fail-closed)")
	}
	shareID := transferIDFor(runID, "settle-operator")
	feeID := transferIDFor(runID, "settle-platform")
	transfers := []tigerbeetle.Transfer{}
	if operatorShareMinor > 0 {
		transfers = append(transfers, tigerbeetle.Transfer{
			ID:              shareID,
			DebitAccountID:  service.topology.OperatorRevenueAccount,
			CreditAccountID: wallet,
			Amount:          tigerbeetle.ToUint128(uint64(operatorShareMinor)),
			Ledger:          service.topology.Ledger,
			Code:            service.topology.Code,
			Flags:           tigerbeetle.TransferFlags{Linked: true}.ToUint16(),
		})
	}
	if platformShareMinor > 0 {
		transfers = append(transfers, tigerbeetle.Transfer{
			ID:              feeID,
			DebitAccountID:  service.topology.OperatorRevenueAccount,
			CreditAccountID: service.topology.PlatformFeeAccount,
			Amount:          tigerbeetle.ToUint128(uint64(platformShareMinor)),
			Ledger:          service.topology.Ledger,
			Code:            service.topology.Code,
		})
	}
	results, err := service.client.CreateTransfers(transfers)
	if err != nil {
		return nil, fmt.Errorf("create linked settlement: %w", err)
	}
	for _, result := range results {
		if result.Status != tigerbeetle.TransferCreated && result.Status != tigerbeetle.TransferExists {
			return nil, fmt.Errorf("linked settlement transfer returned status %v", result.Status)
		}
	}
	ids := make([]string, 0, len(transfers))
	for _, transfer := range transfers {
		ids = append(ids, transfer.ID.String())
	}
	return ids, nil
}
