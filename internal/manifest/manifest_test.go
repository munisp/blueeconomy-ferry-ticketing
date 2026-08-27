package manifest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

func manifestTrip() ticketing.Trip {
	return ticketing.Trip{
		TripID: "trip-1", VesselID: "vessel-1", OperatorID: "op-1",
		RouteReference: "route-1", TerminalReference: "terminal-1",
		ScheduledDeparture: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
		Capacity:           50, SeatsReserved: 2, Status: "SCHEDULED",
	}
}

func manifestTicket(id string, embarked bool) ticketing.Ticket {
	digest, err := ticketing.PassengerDigest("0123456789abcdef", "passenger-"+id)
	if err != nil {
		panic(err)
	}
	return ticketing.Ticket{
		TicketID: id, TripID: "trip-1", OperatorID: "op-1",
		PassengerDigest: digest, State: ticketing.StateIssued, Embarked: embarked,
	}
}

func TestBuildBundleIsFHIRAlignedCollection(t *testing.T) {
	tickets := []ticketing.Ticket{manifestTicket("t-1", true), manifestTicket("t-2", false)}
	bundle, passengers, err := BuildBundle("manifest-1", manifestTrip(), tickets, time.Date(2026, 9, 1, 7, 30, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Equal(t, "Bundle", bundle.ResourceType)
	require.Equal(t, "collection", bundle.Type)
	require.Len(t, bundle.Entry, 3, "Composition header plus one entry per passenger")
	require.Equal(t, 2, bundle.PassengerCount())
	require.Len(t, passengers, 2)

	composition, ok := bundle.Entry[0].Resource.(Composition)
	require.True(t, ok, "first entry must be the Composition header")
	require.Equal(t, "final", composition.Status)
	require.Len(t, composition.Section, 1)
	require.Len(t, composition.Section[0].Entry, 2, "composition section references every passenger entry")

	for _, entry := range bundle.Entry[1:] {
		passenger, ok := entry.Resource.(PassengerEntry)
		require.True(t, ok)
		require.True(t, strings.HasPrefix(entry.FullURL, "urn:uuid:"))
		require.Equal(t, entry.FullURL, passenger.EntryReference)
		require.Len(t, passenger.PassengerDigestSHA256, 64)
	}
	require.True(t, passengers[0].Embarked)
	require.False(t, passengers[1].Embarked)
}

func TestBuildBundleContainsNoRawPII(t *testing.T) {
	tickets := []ticketing.Ticket{manifestTicket("t-1", true)}
	bundle, _, err := BuildBundle("manifest-1", manifestTrip(), tickets, time.Now().UTC())
	require.NoError(t, err)
	serialized, err := json.Marshal(bundle)
	require.NoError(t, err)
	document := string(serialized)
	for _, forbidden := range []string{"passenger-t-1", "name", "phone", "address", "nin", "bvn"} {
		require.NotContains(t, strings.ToLower(document), forbidden, "manifest must not carry raw PII markers")
	}
	require.Contains(t, document, tickets[0].PassengerDigest, "only the salted digest appears")
}

func TestBuildBundleRejectsNonManifestableTickets(t *testing.T) {
	reserved := manifestTicket("t-1", false)
	reserved.State = ticketing.StateReserved
	_, _, err := BuildBundle("manifest-1", manifestTrip(), []ticketing.Ticket{reserved}, time.Now().UTC())
	require.Error(t, err, "RESERVED tickets never appear on a manifest")

	noDigest := manifestTicket("t-2", false)
	noDigest.PassengerDigest = ""
	_, _, err = BuildBundle("manifest-1", manifestTrip(), []ticketing.Ticket{noDigest}, time.Now().UTC())
	require.Error(t, err)
}

func TestBuildBundleFailsClosedOnMissingIdentifiers(t *testing.T) {
	_, _, err := BuildBundle("", manifestTrip(), nil, time.Now().UTC())
	require.Error(t, err)
	trip := manifestTrip()
	trip.VesselID = ""
	_, _, err = BuildBundle("manifest-1", trip, nil, time.Now().UTC())
	require.Error(t, err)
}

func TestDigestIsStable(t *testing.T) {
	tickets := []ticketing.Ticket{manifestTicket("t-1", true)}
	at := time.Date(2026, 9, 1, 7, 30, 0, 0, time.UTC)
	first, _, err := BuildBundle("manifest-1", manifestTrip(), tickets, at)
	require.NoError(t, err)
	second, _, err := BuildBundle("manifest-1", manifestTrip(), tickets, at)
	require.NoError(t, err)
	digestA, err := Digest(first)
	require.NoError(t, err)
	digestB, err := Digest(second)
	require.NoError(t, err)
	require.Equal(t, digestA, digestB)
	require.Len(t, digestA, 64)
}

func TestCompletenessKPI(t *testing.T) {
	record := Manifest{PassengerCount: 48, ExpectedPassengers: 50}
	require.InDelta(t, 0.96, record.Completeness(), 0.0001)
	require.True(t, record.MeetsKPI(0.95))
	require.False(t, record.MeetsKPI(0.99))

	empty := Manifest{PassengerCount: 0, ExpectedPassengers: 0}
	require.Equal(t, 1.0, empty.Completeness())
	require.True(t, empty.MeetsKPI(0.95))

	under := Manifest{PassengerCount: 40, ExpectedPassengers: 50}
	require.False(t, under.MeetsKPI(0.95), "below the 95% KPI")
}
