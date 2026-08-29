package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	sdkworkflow "go.temporal.io/sdk/workflow"
)

func activityRegisterOptions(name string) activity.RegisterOptions {
	return activity.RegisterOptions{Name: name}
}

type ferrySuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
	env *testsuite.TestWorkflowEnvironment
}

func TestFerryWorkflow(t *testing.T) {
	suite.Run(t, new(ferrySuite))
}

func (suite *ferrySuite) SetupTest() {
	suite.env = suite.NewTestWorkflowEnvironment()
}

func (suite *ferrySuite) TearDownTest() {
	suite.env.AssertExpectations(suite.T())
}

func (suite *ferrySuite) register(paused *bool, alerts *[]AdverseWeatherSignal, incomplete *bool) {
	var departed bool
	suite.registerWithDeparture(paused, &departed, alerts, incomplete)
}

func (suite *ferrySuite) registerWithDeparture(paused, departed *bool, alerts *[]AdverseWeatherSignal, incomplete *bool) {
	activities := &Activities{
		PauseBoarding: func(_ context.Context, tripID string) error {
			*paused = true
			return nil
		},
		MarkTripDeparted: func(_ context.Context, tripID string) error {
			*departed = true
			return nil
		},
		EmitWeatherAlert: func(_ context.Context, tripID, routeReference string, alert AdverseWeatherSignal, correlationID string) error {
			*alerts = append(*alerts, alert)
			return nil
		},
		RecordManifestIncomplete: func(_ context.Context, tripID, correlationID string) error {
			*incomplete = true
			return nil
		},
	}
	definition, err := NewFerryWorkflow(activities)
	require.NoError(suite.T(), err)
	suite.env.RegisterWorkflowWithOptions(definition.FerryTicketWorkflow, sdkworkflow.RegisterOptions{Name: "FerryTicketWorkflow"})
	suite.env.RegisterActivityWithOptions(activities.PauseBoarding, activityRegisterOptions(ActivityPauseBoarding))
	suite.env.RegisterActivityWithOptions(activities.MarkTripDeparted, activityRegisterOptions(ActivityMarkTripDeparted))
	suite.env.RegisterActivityWithOptions(activities.EmitWeatherAlert, activityRegisterOptions(ActivityEmitWeatherAlert))
	suite.env.RegisterActivityWithOptions(activities.RecordManifestIncomplete, activityRegisterOptions(ActivityRecordManifestIncomplete))
}

func workflowInput(departure time.Time) Input {
	return Input{
		TicketID: "ticket-1", TripID: "trip-1",
		VesselReference: "vessel-1", RouteReference: "route-1",
		DepartureAt: departure, CorrelationID: "corr-1",
	}
}

func (suite *ferrySuite) TestManifestAndTelemetryCompleteAtDeparture() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{ManifestID: "m-1", ManifestDigestSHA256: "digest", PassengerCount: 42})
	}, time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{TelemetryReference: "tel-1", PayloadDigestSHA256: "digest", ObservedAt: time.Now()})
	}, 90*time.Minute)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	var result Result
	require.NoError(suite.T(), suite.env.GetWorkflowResult(&result))
	require.Equal(suite.T(), PhaseDeparted, result.Phase)
	require.False(suite.T(), paused)
	require.Empty(suite.T(), alerts)
	require.False(suite.T(), incomplete)
}

func (suite *ferrySuite) TestAdverseWeatherWithinThirtyMinutesPausesBoardingAndAlerts() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	alert := AdverseWeatherSignal{
		AlertID: "alert-1", Severity: "HIGH", PhenomenonCode: "HIGH_WIND",
		EffectiveFrom: time.Now(), EffectiveUntil: departure, BulletinReference: "nimasa-bulletin-7",
	}
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{ManifestID: "m-1", ManifestDigestSHA256: "digest", PassengerCount: 42})
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{TelemetryReference: "tel-1", PayloadDigestSHA256: "digest", ObservedAt: time.Now()})
	}, time.Hour)
	// 20 minutes before departure: inside the 30-minute window.
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalAdverseWeather, alert)
	}, 100*time.Minute)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	var result Result
	require.NoError(suite.T(), suite.env.GetWorkflowResult(&result))
	require.Equal(suite.T(), PhaseBoardingPaused, result.Phase)
	require.True(suite.T(), paused, "boarding must be paused within the window")
	require.Len(suite.T(), alerts, 1, "AdverseWeatherAlert must reach the NIMASA topic")
	require.Equal(suite.T(), "HIGH_WIND", alerts[0].PhenomenonCode)
	require.False(suite.T(), incomplete)
}

func (suite *ferrySuite) TestAdverseWeatherOutsideWindowAlertsButDoesNotPause() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{ManifestID: "m-1", ManifestDigestSHA256: "digest", PassengerCount: 1})
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{TelemetryReference: "tel-1", PayloadDigestSHA256: "digest", ObservedAt: time.Now()})
		// One hour before departure: outside the 30-minute window.
		suite.env.SignalWorkflow(SignalAdverseWeather, AdverseWeatherSignal{AlertID: "alert-early", PhenomenonCode: "HEAVY_RAIN"})
	}, time.Hour)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	require.True(suite.T(), len(alerts) == 1, "NIMASA is always notified")
	require.False(suite.T(), paused, "boarding is not paused outside the window")
}

func (suite *ferrySuite) TestDepartureWithoutManifestFailsClosed() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{TelemetryReference: "tel-1", PayloadDigestSHA256: "digest", ObservedAt: time.Now()})
	}, time.Hour)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.Error(suite.T(), suite.env.GetWorkflowError(), "departure without a manifest fails closed")
	require.True(suite.T(), incomplete, "the incomplete manifest is audited")
}

func (suite *ferrySuite) TestMalformedSignalsNeverMarkReadiness() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		// Missing manifest id/digest: rejected.
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{})
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{})
		suite.env.SignalWorkflow(SignalAdverseWeather, AdverseWeatherSignal{})
	}, time.Hour)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.Error(suite.T(), suite.env.GetWorkflowError())
	require.True(suite.T(), incomplete)
	require.Empty(suite.T(), alerts)
}

func (suite *ferrySuite) TestStatusQueryReportsProgress() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{ManifestID: "m-1", ManifestDigestSHA256: "digest", PassengerCount: 10})
	}, time.Hour)
	var observed Status
	suite.env.RegisterDelayedCallback(func() {
		value, err := suite.env.QueryWorkflow(QueryStatus)
		require.NoError(suite.T(), err)
		require.NoError(suite.T(), value.Get(&observed))
	}, 90*time.Minute)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	// Telemetry never arrived but the manifest did: departure proceeds.
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	require.True(suite.T(), observed.ManifestReceived)
	require.False(suite.T(), observed.TelemetryReceived)
}

func (suite *ferrySuite) TestInputValidationFailsClosed() {
	var paused bool
	var alerts []AdverseWeatherSignal
	var incomplete bool
	suite.register(&paused, &alerts, &incomplete)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", Input{})
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.Error(suite.T(), suite.env.GetWorkflowError())
}

// TestDeparturePersistsTripStatus is the FE-6 regression: at the departure
// instant the workflow records the DEPARTED lifecycle state via the activity
// — the historical record never claims SCHEDULED forever — including when
// the manifest is missing.
func (suite *ferrySuite) TestDeparturePersistsTripStatus() {
	var paused, departed, incomplete bool
	var alerts []AdverseWeatherSignal
	suite.registerWithDeparture(&paused, &departed, &alerts, &incomplete)
	departure := time.Now().Add(2 * time.Hour)
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalManifestSubmitted, ManifestSignal{ManifestID: "m-1", ManifestDigestSHA256: "digest", PassengerCount: 5})
		suite.env.SignalWorkflow(SignalTelemetryUpdated, TelemetrySignal{TelemetryReference: "tel-1", PayloadDigestSHA256: "digest", ObservedAt: time.Now()})
	}, time.Hour)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(departure))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	require.True(suite.T(), departed, "the departure activity persists the DEPARTED status")
}

func (suite *ferrySuite) TestDepartureWithoutManifestStillMarksDeparted() {
	var paused, departed, incomplete bool
	var alerts []AdverseWeatherSignal
	suite.registerWithDeparture(&paused, &departed, &alerts, &incomplete)
	suite.env.ExecuteWorkflow("FerryTicketWorkflow", workflowInput(time.Now().Add(2*time.Hour)))
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.Error(suite.T(), suite.env.GetWorkflowError(), "missing manifest still fails closed")
	require.True(suite.T(), departed, "the trip departed physically; the status is persisted even without a manifest")
	require.True(suite.T(), incomplete)
}

func (suite *ferrySuite) TestNewFerryWorkflowFailsClosedWithoutActivities() {
	_, err := NewFerryWorkflow(nil)
	require.Error(suite.T(), err)
	_, err = NewFerryWorkflow(&Activities{})
	require.Error(suite.T(), err)
}
