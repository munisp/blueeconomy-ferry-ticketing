package ledger

import (
	"context"
	"errors"
	"testing"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/stretchr/testify/require"
	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
)

type fakeClient struct {
	transfers []tigerbeetle.Transfer
	accounts  []tigerbeetle.Account
	err       error
	status    tigerbeetle.CreateTransferStatus
	// lookup is the cluster-visible transfer store for LookupTransfers.
	lookup map[tigerbeetle.Uint128]tigerbeetle.Transfer
}

func (client *fakeClient) CreateAccounts(accounts []tigerbeetle.Account) ([]tigerbeetle.CreateAccountResult, error) {
	if client.err != nil {
		return nil, client.err
	}
	client.accounts = append(client.accounts, accounts...)
	return nil, nil
}

func (client *fakeClient) CreateTransfers(transfers []tigerbeetle.Transfer) ([]tigerbeetle.CreateTransferResult, error) {
	if client.err != nil {
		return nil, client.err
	}
	client.transfers = append(client.transfers, transfers...)
	// TigerBeetle returns results only for rejected transfers; an empty result
	// set means every transfer was created (or deduplicated).
	if client.status != 0 {
		return []tigerbeetle.CreateTransferResult{{Status: client.status}}, nil
	}
	return nil, nil
}

func (client *fakeClient) LookupTransfers(ids []tigerbeetle.Uint128) ([]tigerbeetle.Transfer, error) {
	if client.err != nil {
		return nil, client.err
	}
	found := make([]tigerbeetle.Transfer, 0, len(ids))
	for _, id := range ids {
		if transfer, ok := client.lookup[id]; ok {
			found = append(found, transfer)
		}
	}
	return found, nil
}

func testTopology() Topology {
	return Topology{
		Ledger:                   7,
		Code:                     9,
		PassengerClearingAccount: tigerbeetle.ToUint128(1001),
		OperatorRevenueAccount:   tigerbeetle.ToUint128(1002),
		AgentFloatAccount:        tigerbeetle.ToUint128(1003),
		PendingTimeoutSeconds:    900,
	}
}

func TestTopologyValidationFailsClosed(t *testing.T) {
	_, err := New(nil, testTopology())
	require.Error(t, err)

	zero := testTopology()
	zero.Ledger = 0
	_, err = New(&fakeClient{}, zero)
	require.Error(t, err)

	duplicate := testTopology()
	duplicate.AgentFloatAccount = duplicate.OperatorRevenueAccount
	_, err = New(&fakeClient{}, duplicate)
	require.Error(t, err)

	missingTimeout := testTopology()
	missingTimeout.PendingTimeoutSeconds = 0
	_, err = New(&fakeClient{}, missingTimeout)
	require.Error(t, err)
}

func TestReserveCreatesPendingTwoPhaseTransfer(t *testing.T) {
	client := &fakeClient{}
	service, err := New(client, testTopology())
	require.NoError(t, err)
	id, err := service.Reserve(context.Background(), "ticket-1", ticketing.ChannelDirect, 250000)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.Len(t, client.transfers, 1)
	transfer := client.transfers[0]
	pendingFlag := tigerbeetle.TransferFlags{Pending: true}.ToUint16()
	require.Equal(t, pendingFlag, transfer.Flags&pendingFlag, "pending flag set")
	require.Equal(t, testTopology().PassengerClearingAccount, transfer.DebitAccountID)
	require.Equal(t, testTopology().OperatorRevenueAccount, transfer.CreditAccountID)
	require.Equal(t, uint32(900), transfer.Timeout)
	require.Equal(t, tigerbeetle.ToUint128(250000), transfer.Amount)

	// Deterministic: a retry maps to the same transfer ID (cluster dedups).
	again, err := service.Reserve(context.Background(), "ticket-1", ticketing.ChannelDirect, 250000)
	require.NoError(t, err)
	require.Equal(t, id, again)
}

func TestReserveAgentCashInDebitsAgentFloat(t *testing.T) {
	client := &fakeClient{}
	service, err := New(client, testTopology())
	require.NoError(t, err)
	_, err = service.Reserve(context.Background(), "ticket-2", ticketing.ChannelAgentCashIn, 100000)
	require.NoError(t, err)
	require.Equal(t, testTopology().AgentFloatAccount, client.transfers[0].DebitAccountID)
}

func TestPostAndVoidTargetPendingTransfer(t *testing.T) {
	client := &fakeClient{}
	service, err := New(client, testTopology())
	require.NoError(t, err)
	reserveID, err := service.Reserve(context.Background(), "ticket-1", ticketing.ChannelDirect, 250000)
	require.NoError(t, err)

	postID, err := service.Post(context.Background(), reserveID)
	require.NoError(t, err)
	require.NotEmpty(t, postID)
	post := client.transfers[len(client.transfers)-1]
	pending, err := ParseID(reserveID)
	require.NoError(t, err)
	require.Equal(t, pending, post.PendingID)
	require.Equal(t, tigerbeetle.TransferFlags{PostPendingTransfer: true}.ToUint16(), post.Flags)

	require.NoError(t, service.Void(context.Background(), reserveID))
	voided := client.transfers[len(client.transfers)-1]
	require.Equal(t, pending, voided.PendingID)
	require.Equal(t, tigerbeetle.TransferFlags{VoidPendingTransfer: true}.ToUint16(), voided.Flags)
}

func TestRefundMovesFareBackToClearing(t *testing.T) {
	client := &fakeClient{}
	service, err := New(client, testTopology())
	require.NoError(t, err)
	_, err = service.Refund(context.Background(), "ticket-1", 250000)
	require.NoError(t, err)
	refund := client.transfers[len(client.transfers)-1]
	require.Equal(t, testTopology().OperatorRevenueAccount, refund.DebitAccountID)
	require.Equal(t, testTopology().PassengerClearingAccount, refund.CreditAccountID)
}

func TestLedgerFailsClosedOnClusterErrors(t *testing.T) {
	client := &fakeClient{err: errors.New("cluster unreachable")}
	service, err := New(client, testTopology())
	require.NoError(t, err)
	_, err = service.Reserve(context.Background(), "ticket-1", ticketing.ChannelDirect, 1)
	require.Error(t, err)

	rejecting := &fakeClient{status: tigerbeetle.TransferExceedsCredits}
	service, err = New(rejecting, testTopology())
	require.NoError(t, err)
	_, err = service.Reserve(context.Background(), "ticket-1", ticketing.ChannelDirect, 1)
	require.Error(t, err, "non-created transfer status fails closed")
}

// TestResolveReserve pins the reconciler's money-state resolution: posted
// beats everything, an explicit void releases, a pending transfer whose
// pending flag cleared without a companion post/void was auto-voided by the
// timeout, and a missing transfer is unknown.
func TestResolveReserve(t *testing.T) {
	reserveID := transferIDFor("ticket-1", "reserve")
	// Post/void companion IDs derive from the reserve transfer ID string,
	// mirroring ledger.Post/ledger.Void.
	postID := transferIDFor(reserveID.String(), "post")
	voidID := transferIDFor(reserveID.String(), "void")
	pendingTransfer := tigerbeetle.Transfer{ID: reserveID, Flags: tigerbeetle.TransferFlags{Pending: true}.ToUint16()}

	cases := []struct {
		name       string
		cluster    map[tigerbeetle.Uint128]tigerbeetle.Transfer
		wantStatus ticketing.ReserveStatus
		wantPostID bool
	}{
		{
			name:       "posted reserve resolves with the deterministic post id",
			cluster:    map[tigerbeetle.Uint128]tigerbeetle.Transfer{reserveID: pendingTransfer, postID: {ID: postID}},
			wantStatus: ticketing.ReserveStatusPosted,
			wantPostID: true,
		},
		{
			name:       "explicit void releases",
			cluster:    map[tigerbeetle.Uint128]tigerbeetle.Transfer{reserveID: pendingTransfer, voidID: {ID: voidID}},
			wantStatus: ticketing.ReserveStatusReleased,
		},
		{
			name:       "open reserve stays pending",
			cluster:    map[tigerbeetle.Uint128]tigerbeetle.Transfer{reserveID: pendingTransfer},
			wantStatus: ticketing.ReserveStatusPending,
		},
		{
			name: "timeout auto-void clears the pending flag without a companion transfer",
			cluster: map[tigerbeetle.Uint128]tigerbeetle.Transfer{
				reserveID: {ID: reserveID, Flags: 0},
			},
			wantStatus: ticketing.ReserveStatusReleased,
		},
		{
			name:       "unknown reserve",
			cluster:    map[tigerbeetle.Uint128]tigerbeetle.Transfer{},
			wantStatus: ticketing.ReserveStatusUnknown,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := &fakeClient{lookup: testCase.cluster}
			service, err := New(client, testTopology())
			require.NoError(t, err)
			resolution, err := service.ResolveReserve(context.Background(), reserveID.String())
			require.NoError(t, err)
			require.Equal(t, testCase.wantStatus, resolution.Status)
			if testCase.wantPostID {
				require.Equal(t, postID.String(), resolution.PostTransferID)
			} else {
				require.Empty(t, resolution.PostTransferID)
			}
		})
	}

	service, err := New(&fakeClient{err: errors.New("cluster unreachable")}, testTopology())
	require.NoError(t, err)
	_, err = service.ResolveReserve(context.Background(), reserveID.String())
	require.Error(t, err, "lookup failures fail closed")
	_, err = service.ResolveReserve(context.Background(), "not-a-transfer-id")
	require.Error(t, err, "malformed ids fail closed")
}

func TestParseIDRejectsZero(t *testing.T) {
	_, err := ParseID("")
	require.Error(t, err)
	_, err = ParseID("0")
	require.Error(t, err)
	id, err := ParseID("00000000000000000000000000000001")
	require.NoError(t, err)
	require.NotEqual(t, tigerbeetle.Uint128{}, id)
}
