package ticketing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStateMachineApprovedTransitions(t *testing.T) {
	approved := []struct{ from, to State }{
		{StateReserved, StatePaid},
		{StateReserved, StateExpired},
		{StateReserved, StateVoid},
		{StatePaid, StateIssued},
		{StatePaid, StateRefunded},
		{StatePaid, StateVoid},
		{StateIssued, StateRefunded},
		{StateIssued, StateExpired},
		{StateIssued, StateVoid},
	}
	for _, move := range approved {
		require.True(t, ValidTransition(move.from, move.to), "%s -> %s", move.from, move.to)
	}
}

func TestStateMachineRejectsUnapprovedTransitions(t *testing.T) {
	rejected := []struct{ from, to State }{
		{StateReserved, StateIssued},
		{StateReserved, StateRefunded},
		{StatePaid, StateReserved},
		{StatePaid, StateExpired},
		{StateIssued, StatePaid},
		{StateRefunded, StatePaid},
		{StateExpired, StateIssued},
		{StateVoid, StateReserved},
		{StateRefunded, StateVoid},
	}
	for _, move := range rejected {
		require.False(t, ValidTransition(move.from, move.to), "%s -> %s must fail closed", move.from, move.to)
	}
}

func TestTerminalStates(t *testing.T) {
	require.True(t, StateRefunded.Terminal())
	require.True(t, StateExpired.Terminal())
	require.True(t, StateVoid.Terminal())
	require.False(t, StateReserved.Terminal())
	require.False(t, StatePaid.Terminal())
	require.False(t, StateIssued.Terminal())
}

func TestPassengerDigestIsSaltedAndStable(t *testing.T) {
	salt := "0123456789abcdef"
	first, err := PassengerDigest(salt, "passenger-ref-1")
	require.NoError(t, err)
	second, err := PassengerDigest(salt, "passenger-ref-1")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Len(t, first, 64)
	otherSalt, err := PassengerDigest("fedcba9876543210", "passenger-ref-1")
	require.NoError(t, err)
	require.NotEqual(t, first, otherSalt, "digest must depend on the salt")
	otherRef, err := PassengerDigest(salt, "passenger-ref-2")
	require.NoError(t, err)
	require.NotEqual(t, first, otherRef)
}

func TestPassengerDigestFailsClosed(t *testing.T) {
	_, err := PassengerDigest("", "ref")
	require.Error(t, err)
	_, err = PassengerDigest("salt", "  ")
	require.Error(t, err)
}

func TestPurchaseRequestValidate(t *testing.T) {
	valid := PurchaseRequest{
		TripID:         "trip-1",
		PassengerRef:   "ref-1",
		Channel:        ChannelDirect,
		IdempotencyKey: "key-1",
		CorrelationID:  "corr-1",
		Principal:      "subject-1",
	}
	require.NoError(t, valid.Validate())

	missingTrip := valid
	missingTrip.TripID = ""
	require.Error(t, missingTrip.Validate())

	agentWithoutID := valid
	agentWithoutID.Channel = ChannelAgentCashIn
	require.Error(t, agentWithoutID.Validate(), "agent cash-in requires agent_id")
	agentWithoutID.AgentID = "agent-1"
	require.NoError(t, agentWithoutID.Validate())

	badChannel := valid
	badChannel.Channel = "CRYPTO"
	require.Error(t, badChannel.Validate())

	missingKey := valid
	missingKey.IdempotencyKey = ""
	require.Error(t, missingKey.Validate())
}

func TestTripCapacity(t *testing.T) {
	trip := Trip{Capacity: 2, SeatsReserved: 1}
	require.True(t, trip.HasCapacity())
	trip.SeatsReserved = 2
	require.False(t, trip.HasCapacity())
	trip.ScheduledDeparture = time.Now().Add(time.Hour)
	require.False(t, trip.HasCapacity())
}
