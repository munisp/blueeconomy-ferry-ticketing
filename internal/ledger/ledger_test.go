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
	return nil, nil
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

func TestParseIDRejectsZero(t *testing.T) {
	_, err := ParseID("")
	require.Error(t, err)
	_, err = ParseID("0")
	require.Error(t, err)
	id, err := ParseID("00000000000000000000000000000001")
	require.NoError(t, err)
	require.NotEqual(t, tigerbeetle.Uint128{}, id)
}
