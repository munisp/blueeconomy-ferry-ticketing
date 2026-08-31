package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/testsuite"
	sdkworkflow "go.temporal.io/sdk/workflow"
)

var advisoryStart = time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)

type advisorySuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
	env *testsuite.TestWorkflowEnvironment

	departures   []DepartureWindow
	suspended    []suspendCall
	resumed      []string
	suspendCalls int
}

type suspendCall struct {
	tripID string
	detail SuspensionDetail
}

func TestRouteAdvisoryWorkflow(t *testing.T) {
	suite.Run(t, new(advisorySuite))
}

func (suite *advisorySuite) SetupTest() {
	suite.env = suite.NewTestWorkflowEnvironment()
	suite.env.SetStartTime(advisoryStart)
	suite.departures = []DepartureWindow{
		{TripID: "trip-1", ScheduledDeparture: advisoryStart.Add(4 * time.Hour), Status: "SCHEDULED"},
		{TripID: "trip-2", ScheduledDeparture: advisoryStart.Add(6 * time.Hour), Status: "SCHEDULED"},
	}
	suite.suspended = nil
	suite.resumed = nil
	suite.suspendCalls = 0

	activities := &AdvisoryActivities{
		ListAffectedDepartures: func(_ context.Context, routeReference string, from, until time.Time) ([]DepartureWindow, error) {
			return suite.departures, nil
		},
		SuspendDeparture: func(_ context.Context, tripID string, detail SuspensionDetail, correlationID string) (bool, error) {
			suite.suspendCalls++
			suite.suspended = append(suite.suspended, suspendCall{tripID: tripID, detail: detail})
			return true, nil
		},
		ResumeAdvisoryDepartures: func(_ context.Context, advisoryID, correlationID string) ([]string, error) {
			suite.resumed = append(suite.resumed, advisoryID)
			return []string{"trip-1", "trip-2"}, nil
		},
	}
	definition, err := NewRouteAdvisoryWorkflow(activities)
	require.NoError(suite.T(), err)
	suite.env.RegisterWorkflowWithOptions(definition.RouteAdvisoryWorkflow, sdkworkflow.RegisterOptions{Name: RouteAdvisoryWorkflowName})
	suite.env.RegisterActivityWithOptions(activities.ListAffectedDepartures, activityRegisterOptions(ActivityListAffectedDepartures))
	suite.env.RegisterActivityWithOptions(activities.SuspendDeparture, activityRegisterOptions(ActivitySuspendDeparture))
	suite.env.RegisterActivityWithOptions(activities.ResumeAdvisoryDepartures, activityRegisterOptions(ActivityResumeAdvisoryDepartures))
}

func (suite *advisorySuite) TearDownTest() {
	suite.env.AssertExpectations(suite.T())
}

func advisorySignal(id, msgType string, from, until time.Time) RouteAdvisorySignal {
	return RouteAdvisorySignal{
		AdvisoryID:        id,
		MsgType:           msgType,
		Severity:          "Severe",
		PhenomenonCode:    "HIGH_SIGNIFICANT_WAVE_HEIGHT",
		ZoneID:            "hz-lagos-approach",
		EffectiveFrom:     from,
		EffectiveUntil:    until,
		BulletinReference: "sha256:abc",
		CorrelationID:     "corr-" + id,
	}
}

func (suite *advisorySuite) execute(signals ...RouteAdvisorySignal) RouteAdvisoryResult {
	for _, signal := range signals {
		signal := signal
		suite.env.RegisterDelayedCallback(func() {
			suite.env.SignalWorkflow(SignalRouteAdvisory, signal)
		}, time.Minute)
	}
	suite.env.ExecuteWorkflow(RouteAdvisoryWorkflowName, RouteAdvisoryInput{RouteReference: "lagos-apapa", CorrelationID: "corr-start"})
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
	var result RouteAdvisoryResult
	require.NoError(suite.T(), suite.env.GetWorkflowResult(&result))
	return result
}

func (suite *advisorySuite) TestAlertSuspendsAndExpiryResumes() {
	result := suite.execute(advisorySignal("moa-1", AdvisoryMsgAlert, advisoryStart, advisoryStart.Add(30*time.Minute)))
	require.Equal(suite.T(), 1, result.Processed)
	require.Equal(suite.T(), "lagos-apapa", result.RouteReference)
	// Both affected departures were suspended with the advisory detail.
	require.Len(suite.T(), suite.suspended, 2)
	require.Equal(suite.T(), "trip-1", suite.suspended[0].tripID)
	require.Equal(suite.T(), "trip-2", suite.suspended[1].tripID)
	require.Equal(suite.T(), "moa-1", suite.suspended[0].detail.AdvisoryID)
	require.Equal(suite.T(), "Severe", suite.suspended[0].detail.Severity)
	// The advisory window expired (30 minutes) before the idle exit, so the
	// departures auto-resumed.
	require.Equal(suite.T(), []string{"moa-1"}, suite.resumed)
}

func (suite *advisorySuite) TestCancelResumesBeforeExpiry() {
	alert := advisorySignal("moa-2", AdvisoryMsgAlert, advisoryStart.Add(2*time.Hour), advisoryStart.Add(48*time.Hour))
	cancel := advisorySignal("moa-3", AdvisoryMsgCancel, time.Time{}, time.Time{})
	cancel.ReferencesAdvisoryID = "moa-2"
	result := suite.execute(alert, cancel)
	require.Equal(suite.T(), 2, result.Processed)
	require.Len(suite.T(), suite.suspended, 2)
	// Resume happened on the cancel, not on window expiry (48h out).
	require.Equal(suite.T(), []string{"moa-2"}, suite.resumed)
}

func (suite *advisorySuite) TestUpdateReEvaluatesSuspension() {
	alert := advisorySignal("moa-4", AdvisoryMsgAlert, advisoryStart, advisoryStart.Add(time.Hour))
	update := advisorySignal("moa-4", AdvisoryMsgUpdate, advisoryStart.Add(90*time.Minute), advisoryStart.Add(3*time.Hour))
	result := suite.execute(alert, update)
	require.Equal(suite.T(), 2, result.Processed)
	// Suspend (alert), resume (update releases the previous set), suspend
	// (update window), resume (update window expiry).
	require.Len(suite.T(), suite.suspended, 4)
	require.Equal(suite.T(), []string{"moa-4", "moa-4"}, suite.resumed)
}

func (suite *advisorySuite) TestMalformedSignalIgnored() {
	malformed := advisorySignal("", AdvisoryMsgAlert, advisoryStart.Add(time.Hour), advisoryStart.Add(2*time.Hour))
	result := suite.execute(malformed)
	require.Equal(suite.T(), 0, result.Processed)
	require.Empty(suite.T(), suite.suspended)
	require.Empty(suite.T(), suite.resumed)
}

func (suite *advisorySuite) TestCancelWithoutReferenceIgnored() {
	cancel := advisorySignal("moa-5", AdvisoryMsgCancel, time.Time{}, time.Time{})
	result := suite.execute(cancel)
	require.Equal(suite.T(), 0, result.Processed)
	require.Empty(suite.T(), suite.resumed)
}

func (suite *advisorySuite) TestIdleExitWithNoAdvisories() {
	result := suite.execute()
	require.Equal(suite.T(), 0, result.Processed)
}

func (suite *advisorySuite) TestQueryStatusReportsActive() {
	suite.env.RegisterDelayedCallback(func() {
		suite.env.SignalWorkflow(SignalRouteAdvisory, advisorySignal("moa-6", AdvisoryMsgAlert, advisoryStart.Add(time.Hour), advisoryStart.Add(48*time.Hour)))
	}, time.Minute)
	suite.env.RegisterDelayedCallback(func() {
		value, err := suite.env.QueryWorkflow(QueryRouteAdvisoryStatus)
		require.NoError(suite.T(), err)
		var status RouteAdvisoryStatus
		require.NoError(suite.T(), value.Get(&status))
		require.Equal(suite.T(), "lagos-apapa", status.RouteReference)
		require.Len(suite.T(), status.Active, 1)
		require.Equal(suite.T(), "moa-6", status.Active[0].AdvisoryID)
		require.Equal(suite.T(), []string{"trip-1", "trip-2"}, status.Active[0].SuspendedTripIDs)
		require.Equal(suite.T(), 1, status.Processed)
	}, 2*time.Minute)
	suite.env.ExecuteWorkflow(RouteAdvisoryWorkflowName, RouteAdvisoryInput{RouteReference: "lagos-apapa", CorrelationID: "corr-start"})
	require.True(suite.T(), suite.env.IsWorkflowCompleted())
	require.NoError(suite.T(), suite.env.GetWorkflowError())
}

func TestNewRouteAdvisoryWorkflowFailClosed(t *testing.T) {
	_, err := NewRouteAdvisoryWorkflow(nil)
	require.Error(t, err)
	_, err = NewRouteAdvisoryWorkflow(&AdvisoryActivities{})
	require.Error(t, err)
}

func TestRouteAdvisoryInputValidation(t *testing.T) {
	require.Error(t, RouteAdvisoryInput{}.Validate())
	require.Error(t, RouteAdvisoryInput{RouteReference: "r"}.Validate())
	require.NoError(t, RouteAdvisoryInput{RouteReference: "r", CorrelationID: "c"}.Validate())
}

func TestRouteAdvisorySignalValidation(t *testing.T) {
	require.Error(t, RouteAdvisorySignal{}.Validate())
	require.Error(t, advisorySignal("a", AdvisoryMsgAlert, advisoryStart.Add(2*time.Hour), advisoryStart).Validate())
	require.Error(t, advisorySignal("a", "Other", advisoryStart, advisoryStart.Add(time.Hour)).Validate())
	require.NoError(t, advisorySignal("a", AdvisoryMsgAlert, advisoryStart, advisoryStart.Add(time.Hour)).Validate())
}
