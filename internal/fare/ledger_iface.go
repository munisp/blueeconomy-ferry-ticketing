package fare

import (
	"context"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ledger"
)

// AccountLedger is the BlueFare account boundary against TigerBeetle
// (implemented by ledger.Service). Fare accounts carry
// DEBITS_MUST_NOT_EXCEED_CREDITS cluster-side; every transfer ID is
// deterministic so replays dedupe at the cluster.
type AccountLedger interface {
	// EnsureAccount provisions one account (constrained = no negative balance).
	EnsureAccount(id tigerbeetle.Uint128, constrained bool) error
	// ReserveFromAccount creates the two-phase hold debiting a fare account.
	ReserveFromAccount(ctx context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error)
	// CreditAccount settles a verified top-up into a fare account.
	CreditAccount(ctx context.Context, reference, fareAccountIDHex string, amountNGNMinor int64, source ledger.FundingSource) (string, error)
	// DebitAccount settles one offline debit (or direct charge) from a fare
	// account; an insufficient balance is rejected by the cluster.
	DebitAccount(ctx context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error)
	// RefundToAccount moves value from operator revenue back to an account.
	RefundToAccount(ctx context.Context, reference, fareAccountIDHex string, amountNGNMinor int64) (string, error)
	// LinkedSettlement executes the operator split as an atomic linked chain.
	LinkedSettlement(ctx context.Context, runID, operatorWalletIDHex string, operatorShareMinor, platformShareMinor int64) ([]string, error)
}
