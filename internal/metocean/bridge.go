package metocean

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"

	ferryworkflow "github.com/munisp/blueeconomy-ferry-ticketing/internal/workflow"
)

// TemporalSignaler is the narrow Temporal client surface the bridge needs;
// the production client satisfies it and tests substitute fakes.
type TemporalSignaler interface {
	SignalWithStartWorkflow(ctx context.Context, workflowID, signalName string, signalArg any,
		options client.StartWorkflowOptions, workflow any, workflowArgs ...any) (client.WorkflowRun, error)
}

// Bridge dispatches verified advisories to the per-route Temporal
// workflows: it resolves the hazard zone to ferry routes (configuration is
// the sole source of truth — unmapped zones are dead-lettered by the
// consumer, never guessed), gates on the configured suspend severities, and
// signal-with-starts one RouteAdvisoryWorkflow per affected route.
type Bridge struct {
	signaler TemporalSignaler
	config   Config
	metrics  *Metrics
	logger   *slog.Logger
}

// NewBridge fails closed on missing dependencies.
func NewBridge(signaler TemporalSignaler, config Config, metrics *Metrics, logger *slog.Logger) (*Bridge, error) {
	if signaler == nil {
		return nil, errors.New("temporal signaler is required")
	}
	if len(config.ZoneRoutes) == 0 {
		return nil, errors.New("zone-to-route map is required (fail-closed)")
	}
	if config.TemporalTaskQueue == "" {
		return nil, errors.New("temporal task queue is required")
	}
	if metrics == nil || logger == nil {
		return nil, errors.New("metrics and logger are required")
	}
	return &Bridge{signaler: signaler, config: config, metrics: metrics, logger: logger}, nil
}

// Dispatch implements Dispatcher.
func (bridge *Bridge) Dispatch(ctx context.Context, advisory Advisory) error {
	routes, ok := bridge.config.RoutesForZone(advisory.ZoneID)
	if !ok {
		return &UnmappedZoneError{ZoneID: advisory.ZoneID}
	}
	// Severity gate: below-threshold Alert/Update advisories are recorded and
	// metered but never suspend departures. Cancel advisories always pass —
	// resumption must never be gated.
	if advisory.MsgType != MsgTypeCancel && !bridge.config.SuspendsOn(advisory.Severity) {
		bridge.logger.Info("advisory below suspend severity; recorded only",
			"advisory", advisory.AdvisoryID, "severity", advisory.Severity, "zone", advisory.ZoneID)
		bridge.metrics.skipped.Add(ctx, 1)
		return nil
	}
	signal := ferryworkflow.RouteAdvisorySignal{
		AdvisoryID:           advisory.AdvisoryID,
		MsgType:              advisory.MsgType,
		ReferencesAdvisoryID: advisory.ReferencesAdvisoryID,
		Severity:             advisory.Severity,
		PhenomenonCode:       advisory.PhenomenonCode,
		ZoneID:               advisory.ZoneID,
		EffectiveFrom:        advisory.EffectiveFrom,
		EffectiveUntil:       advisory.EffectiveUntil,
		BulletinReference:    advisory.BulletinReference,
		CorrelationID:        advisory.CorrelationID,
	}
	for _, route := range routes {
		workflowID := ferryworkflow.WorkflowIDPrefix + route
		_, err := bridge.signaler.SignalWithStartWorkflow(ctx,
			workflowID,
			ferryworkflow.SignalRouteAdvisory, signal,
			client.StartWorkflowOptions{
				ID:        workflowID,
				TaskQueue: bridge.config.TemporalTaskQueue,
				// A route workflow that exited idle must restart on the next
				// advisory for the same route id.
				WorkflowIDReusePolicy: enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
			},
			ferryworkflow.RouteAdvisoryWorkflowName,
			ferryworkflow.RouteAdvisoryInput{RouteReference: route, CorrelationID: advisory.CorrelationID},
		)
		if err != nil {
			return fmt.Errorf("signal route workflow %s: %w", workflowID, err)
		}
		bridge.logger.Info("advisory signaled to route workflow",
			"advisory", advisory.AdvisoryID, "msg_type", advisory.MsgType, "route", route)
	}
	return nil
}
