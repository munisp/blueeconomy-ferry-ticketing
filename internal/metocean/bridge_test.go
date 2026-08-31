package metocean

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/client"

	ferryworkflow "github.com/munisp/blueeconomy-ferry-ticketing/internal/workflow"
)

type signalCall struct {
	workflowID string
	signalName string
	signal     ferryworkflow.RouteAdvisorySignal
	options    client.StartWorkflowOptions
	workflow   any
	input      ferryworkflow.RouteAdvisoryInput
}

type fakeSignaler struct {
	mu    sync.Mutex
	calls []signalCall
	err   error
}

func (signaler *fakeSignaler) SignalWithStartWorkflow(_ context.Context, workflowID, signalName string, signalArg any,
	options client.StartWorkflowOptions, workflow any, workflowArgs ...any) (client.WorkflowRun, error) {
	signaler.mu.Lock()
	defer signaler.mu.Unlock()
	if signaler.err != nil {
		return nil, signaler.err
	}
	call := signalCall{workflowID: workflowID, signalName: signalName, options: options, workflow: workflow}
	if signal, ok := signalArg.(ferryworkflow.RouteAdvisorySignal); ok {
		call.signal = signal
	}
	if len(workflowArgs) == 1 {
		if input, ok := workflowArgs[0].(ferryworkflow.RouteAdvisoryInput); ok {
			call.input = input
		}
	}
	signaler.calls = append(signaler.calls, call)
	return nil, nil
}

func bridgeFixture(t *testing.T, signaler *fakeSignaler) *Bridge {
	t.Helper()
	metrics, err := NewMetrics(noopMeter())
	require.NoError(t, err)
	bridge, err := NewBridge(signaler, Config{
		ZoneRoutes:        map[string][]string{"hz-lagos-approach": {"lagos-apapa", "lagos-ikoyi"}},
		SuspendSeverities: map[string]struct{}{"Severe": {}, "Extreme": {}},
		TemporalTaskQueue: "ferry-task-queue",
	}, metrics, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	return bridge
}

func testAdvisory(msgType, severity, zoneID string) Advisory {
	return Advisory{
		EventID:              "evt-1",
		CorrelationID:        "corr-1",
		Producer:             AdvisoryProducer,
		AdvisoryID:           "moa-1",
		MsgType:              msgType,
		Severity:             severity,
		PhenomenonCode:       "HIGH_SIGNIFICANT_WAVE_HEIGHT",
		ZoneID:               zoneID,
		EffectiveFrom:        time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC),
		EffectiveUntil:       time.Date(2026, 8, 30, 6, 0, 0, 0, time.UTC),
		BulletinReference:    "sha256:abc",
		ReferencesAdvisoryID: "moa-0",
	}
}

func TestBridgeSignalsEveryMappedRoute(t *testing.T) {
	signaler := &fakeSignaler{}
	bridge := bridgeFixture(t, signaler)
	require.NoError(t, bridge.Dispatch(context.Background(), testAdvisory(MsgTypeAlert, "Severe", "hz-lagos-approach")))
	signaler.mu.Lock()
	defer signaler.mu.Unlock()
	require.Len(t, signaler.calls, 2)
	ids := []string{signaler.calls[0].workflowID, signaler.calls[1].workflowID}
	require.ElementsMatch(t, []string{"metocean-route-lagos-apapa", "metocean-route-lagos-ikoyi"}, ids)
	for _, call := range signaler.calls {
		require.Equal(t, ferryworkflow.SignalRouteAdvisory, call.signalName)
		require.Equal(t, ferryworkflow.RouteAdvisoryWorkflowName, call.workflow)
		require.Equal(t, "ferry-task-queue", call.options.TaskQueue)
		require.Equal(t, call.workflowID, call.options.ID)
		require.Equal(t, "moa-1", call.signal.AdvisoryID)
		require.Equal(t, MsgTypeAlert, call.signal.MsgType)
		require.Equal(t, "corr-1", call.input.CorrelationID)
	}
}

func TestBridgeSkipsBelowThresholdSeverity(t *testing.T) {
	signaler := &fakeSignaler{}
	bridge := bridgeFixture(t, signaler)
	require.NoError(t, bridge.Dispatch(context.Background(), testAdvisory(MsgTypeAlert, "Moderate", "hz-lagos-approach")))
	signaler.mu.Lock()
	defer signaler.mu.Unlock()
	require.Empty(t, signaler.calls)
}

func TestBridgeCancelBypassesSeverityGate(t *testing.T) {
	signaler := &fakeSignaler{}
	bridge := bridgeFixture(t, signaler)
	require.NoError(t, bridge.Dispatch(context.Background(), testAdvisory(MsgTypeCancel, "Minor", "hz-lagos-approach")))
	signaler.mu.Lock()
	defer signaler.mu.Unlock()
	require.Len(t, signaler.calls, 2)
	require.Equal(t, MsgTypeCancel, signaler.calls[0].signal.MsgType)
	require.Equal(t, "moa-0", signaler.calls[0].signal.ReferencesAdvisoryID)
}

func TestBridgeUnmappedZoneFailsClosed(t *testing.T) {
	signaler := &fakeSignaler{}
	bridge := bridgeFixture(t, signaler)
	err := bridge.Dispatch(context.Background(), testAdvisory(MsgTypeAlert, "Extreme", "hz-nowhere"))
	var unmapped *UnmappedZoneError
	require.ErrorAs(t, err, &unmapped)
	require.Equal(t, "hz-nowhere", unmapped.ZoneID)
	signaler.mu.Lock()
	defer signaler.mu.Unlock()
	require.Empty(t, signaler.calls)
}

func TestBridgePropagatesSignalerFailure(t *testing.T) {
	signaler := &fakeSignaler{err: errors.New("temporal unavailable")}
	bridge := bridgeFixture(t, signaler)
	require.Error(t, bridge.Dispatch(context.Background(), testAdvisory(MsgTypeAlert, "Severe", "hz-lagos-approach")))
}

func TestNewBridgeFailClosed(t *testing.T) {
	metrics, err := NewMetrics(noopMeter())
	require.NoError(t, err)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	_, err = NewBridge(nil, Config{ZoneRoutes: map[string][]string{"z": {"r"}}, TemporalTaskQueue: "q"}, metrics, logger)
	require.Error(t, err)
	_, err = NewBridge(&fakeSignaler{}, Config{TemporalTaskQueue: "q"}, metrics, logger)
	require.Error(t, err)
	_, err = NewBridge(&fakeSignaler{}, Config{ZoneRoutes: map[string][]string{"z": {"r"}}}, metrics, logger)
	require.Error(t, err)
}
