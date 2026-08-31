package workflow

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.temporal.io/sdk/workflow"
)

// RouteAdvisoryWorkflow: one long-lived workflow per ferry route consumes
// verified met-ocean advisories (signaled by the met-ocean bridge), suspends
// scheduled departures overlapping the advisory window, records the audit
// trail and passenger-notification outbox entries, and auto-resumes when a
// CAP Cancel advisory arrives or the advisory window expires. The workflow
// exits after an idle period with no active advisories; the next advisory
// signal-with-starts a fresh run.
const (
	// SignalRouteAdvisory carries one verified met-ocean advisory.
	SignalRouteAdvisory = "metocean.advisory"

	// QueryRouteAdvisoryStatus returns the current workflow status.
	QueryRouteAdvisoryStatus = "metocean.status"

	// ActivityListAffectedDepartures lists the route's open departures whose
	// scheduled departure falls inside the advisory window.
	ActivityListAffectedDepartures = "metocean.list-affected-departures"
	// ActivitySuspendDeparture suspends one departure with its audit record
	// and passenger-notification outbox entry in one transaction.
	ActivitySuspendDeparture = "metocean.suspend-departure"
	// ActivityResumeAdvisoryDepartures resumes every departure still
	// suspended by one advisory (cancel or window expiry), with audit and
	// notification outbox entries.
	ActivityResumeAdvisoryDepartures = "metocean.resume-advisory-departures"

	// routeAdvisoryIdleTimeout bounds workflow history: with no active
	// advisories and no signals for this long the run completes; the next
	// advisory starts a fresh run via signal-with-start.
	routeAdvisoryIdleTimeout = 24 * time.Hour
)

// CAP message types the workflow distinguishes.
const (
	AdvisoryMsgAlert  = "Alert"
	AdvisoryMsgUpdate = "Update"
	AdvisoryMsgCancel = "Cancel"
)

// RouteAdvisoryWorkflowName is the registered workflow type name; the bridge
// derives per-route workflow ids as WorkflowIDPrefix + route reference.
const (
	RouteAdvisoryWorkflowName = "RouteAdvisoryWorkflow"
	WorkflowIDPrefix          = "metocean-route-"
)

// RouteAdvisoryInput starts one per-route advisory workflow.
type RouteAdvisoryInput struct {
	RouteReference string `json:"route_reference"`
	CorrelationID  string `json:"correlation_id"`
}

// Validate fails closed on malformed input.
func (input RouteAdvisoryInput) Validate() error {
	if input.RouteReference == "" {
		return errors.New("route reference is required")
	}
	if input.CorrelationID == "" {
		return errors.New("correlation id is required")
	}
	return nil
}

// RouteAdvisorySignal carries one verified, parsed met-ocean advisory. The
// bridge derives it from the signed envelope; the workflow never sees raw
// event payloads.
type RouteAdvisorySignal struct {
	AdvisoryID           string    `json:"advisory_id"`
	MsgType              string    `json:"msg_type"`
	ReferencesAdvisoryID string    `json:"references_advisory_id"`
	Severity             string    `json:"severity"`
	PhenomenonCode       string    `json:"phenomenon_code"`
	ZoneID               string    `json:"zone_id"`
	EffectiveFrom        time.Time `json:"effective_from"`
	EffectiveUntil       time.Time `json:"effective_until"`
	BulletinReference    string    `json:"bulletin_reference"`
	CorrelationID        string    `json:"correlation_id"`
}

// Validate fails closed on a malformed advisory signal.
func (signal RouteAdvisorySignal) Validate() error {
	if signal.AdvisoryID == "" {
		return errors.New("advisory id is required")
	}
	switch signal.MsgType {
	case AdvisoryMsgAlert, AdvisoryMsgUpdate:
		if signal.EffectiveFrom.IsZero() || signal.EffectiveUntil.IsZero() || !signal.EffectiveFrom.Before(signal.EffectiveUntil) {
			return errors.New("advisory window must be a non-empty interval")
		}
	case AdvisoryMsgCancel:
		if signal.ReferencesAdvisoryID == "" {
			return errors.New("cancel advisory must reference the advisory it terminates")
		}
	default:
		return fmt.Errorf("advisory msg type %q is not Alert, Update or Cancel", signal.MsgType)
	}
	if signal.CorrelationID == "" {
		return errors.New("correlation id is required")
	}
	return nil
}

// SuspensionDetail carries the advisory context persisted on the audit
// record and the passenger-notification outbox entry.
type SuspensionDetail struct {
	AdvisoryID        string    `json:"advisory_id"`
	Severity          string    `json:"severity"`
	PhenomenonCode    string    `json:"phenomenon_code"`
	ZoneID            string    `json:"zone_id"`
	EffectiveFrom     time.Time `json:"effective_from"`
	EffectiveUntil    time.Time `json:"effective_until"`
	BulletinReference string    `json:"bulletin_reference"`
}

// DepartureWindow is one open scheduled departure overlapping an advisory
// window.
type DepartureWindow struct {
	TripID             string    `json:"trip_id"`
	ScheduledDeparture time.Time `json:"scheduled_departure"`
	Status             string    `json:"status"`
}

// ActiveAdvisory is one advisory currently suspending departures.
type ActiveAdvisory struct {
	AdvisoryID       string    `json:"advisory_id"`
	Severity         string    `json:"severity"`
	PhenomenonCode   string    `json:"phenomenon_code"`
	EffectiveUntil   time.Time `json:"effective_until"`
	SuspendedTripIDs []string  `json:"suspended_trip_ids"`
}

// RouteAdvisoryStatus is the queryable workflow state.
type RouteAdvisoryStatus struct {
	RouteReference string           `json:"route_reference"`
	Active         []ActiveAdvisory `json:"active"`
	Processed      int              `json:"processed"`
}

// RouteAdvisoryResult reports the terminal workflow outcome (idle exit).
type RouteAdvisoryResult struct {
	RouteReference string `json:"route_reference"`
	Processed      int    `json:"processed"`
}

// AdvisoryActivities groups the durable side effects the route advisory
// workflow invokes. Each field maps to a Temporal activity implemented
// against PostgreSQL in production and mocked in tests.
type AdvisoryActivities struct {
	// ListAffectedDepartures returns the route's open (SCHEDULED or
	// BOARDING_PAUSED) departures inside [from, until].
	ListAffectedDepartures func(ctx context.Context, routeReference string, from, until time.Time) ([]DepartureWindow, error)
	// SuspendDeparture transitions one departure to SUSPENDED with the audit
	// record and notification outbox entry in one transaction. It is
	// idempotent per (trip, advisory) and reports whether the trip was newly
	// suspended.
	SuspendDeparture func(ctx context.Context, tripID string, detail SuspensionDetail, correlationID string) (bool, error)
	// ResumeAdvisoryDepartures resumes every departure still suspended by
	// the advisory (and by no other active advisory), marks the audit
	// records resumed and writes notification outbox entries. It is
	// idempotent and returns the resumed trip ids.
	ResumeAdvisoryDepartures func(ctx context.Context, advisoryID, correlationID string) ([]string, error)
}

// RouteAdvisoryWorkflow binds the workflow definition to its activity
// dependencies (function values are not serializable workflow arguments).
type RouteAdvisoryWorkflow struct{ activities *AdvisoryActivities }

// NewRouteAdvisoryWorkflow fails closed when activities are absent.
func NewRouteAdvisoryWorkflow(activities *AdvisoryActivities) (*RouteAdvisoryWorkflow, error) {
	if activities == nil || activities.ListAffectedDepartures == nil || activities.SuspendDeparture == nil || activities.ResumeAdvisoryDepartures == nil {
		return nil, errors.New("route advisory workflow activities are required")
	}
	return &RouteAdvisoryWorkflow{activities: activities}, nil
}

// RouteAdvisoryWorkflow drives one route's operational response to met-ocean
// advisories: Alert/Update advisories suspend overlapping departures, Cancel
// advisories and window expiries resume them. Malformed signals are ignored
// (fail closed: a bad signal never mutates operational state); activity
// failures propagate and retry per the Temporal retry policy.
func (definition *RouteAdvisoryWorkflow) RouteAdvisoryWorkflow(ctx workflow.Context, input RouteAdvisoryInput) (RouteAdvisoryResult, error) {
	if err := input.Validate(); err != nil {
		return RouteAdvisoryResult{}, err
	}
	logger := workflow.GetLogger(ctx)
	active := make(map[string]ActiveAdvisory)
	processed := 0
	status := RouteAdvisoryStatus{RouteReference: input.RouteReference, Active: make([]ActiveAdvisory, 0)}
	if err := workflow.SetQueryHandler(ctx, QueryRouteAdvisoryStatus, func() (RouteAdvisoryStatus, error) {
		status.Active = make([]ActiveAdvisory, 0, len(active))
		for _, advisory := range active {
			status.Active = append(status.Active, advisory)
		}
		sort.Slice(status.Active, func(i, j int) bool { return status.Active[i].AdvisoryID < status.Active[j].AdvisoryID })
		status.Processed = processed
		return status, nil
	}); err != nil {
		return RouteAdvisoryResult{}, fmt.Errorf("register status query: %w", err)
	}

	actx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 2 * time.Minute})
	signalChannel := workflow.GetSignalChannel(ctx, SignalRouteAdvisory)

	// resume terminates one advisory: every departure it still suspends (and
	// no other active advisory suspends) returns to SCHEDULED, with audit and
	// notification records. The activity is idempotent.
	resume := func(advisoryID, correlationID string) error {
		if err := workflow.ExecuteActivity(actx, ActivityResumeAdvisoryDepartures, advisoryID, correlationID).Get(actx, nil); err != nil {
			return fmt.Errorf("resume advisory %s departures: %w", advisoryID, err)
		}
		delete(active, advisoryID)
		return nil
	}

	handleSignal := func(signal RouteAdvisorySignal) error {
		if err := signal.Validate(); err != nil {
			// Fail closed: a malformed signal never mutates operational state.
			logger.Warn("ignoring malformed advisory signal", "error", err.Error())
			return nil
		}
		processed++
		if signal.MsgType == AdvisoryMsgCancel {
			if _, tracked := active[signal.ReferencesAdvisoryID]; tracked {
				logger.Info("cancel advisory received; resuming departures",
					"advisory", signal.ReferencesAdvisoryID, "cancel", signal.AdvisoryID)
			}
			// Resume is idempotent and also covers advisories whose track
			// record predates this workflow run.
			return resume(signal.ReferencesAdvisoryID, signal.CorrelationID)
		}
		if _, tracked := active[signal.AdvisoryID]; tracked {
			// Update of a tracked advisory: release the previous suspension
			// set, then re-evaluate against the new window.
			if err := resume(signal.AdvisoryID, signal.CorrelationID); err != nil {
				return err
			}
		}
		var departures []DepartureWindow
		if err := workflow.ExecuteActivity(actx, ActivityListAffectedDepartures,
			input.RouteReference, signal.EffectiveFrom, signal.EffectiveUntil).Get(actx, &departures); err != nil {
			return fmt.Errorf("list affected departures for route %s: %w", input.RouteReference, err)
		}
		detail := SuspensionDetail{
			AdvisoryID:        signal.AdvisoryID,
			Severity:          signal.Severity,
			PhenomenonCode:    signal.PhenomenonCode,
			ZoneID:            signal.ZoneID,
			EffectiveFrom:     signal.EffectiveFrom,
			EffectiveUntil:    signal.EffectiveUntil,
			BulletinReference: signal.BulletinReference,
		}
		suspended := make([]string, 0, len(departures))
		for _, departure := range departures {
			var newly bool
			if err := workflow.ExecuteActivity(actx, ActivitySuspendDeparture,
				departure.TripID, detail, signal.CorrelationID).Get(actx, &newly); err != nil {
				return fmt.Errorf("suspend departure %s: %w", departure.TripID, err)
			}
			if newly {
				suspended = append(suspended, departure.TripID)
			}
		}
		sort.Strings(suspended)
		active[signal.AdvisoryID] = ActiveAdvisory{
			AdvisoryID:       signal.AdvisoryID,
			Severity:         signal.Severity,
			PhenomenonCode:   signal.PhenomenonCode,
			EffectiveUntil:   signal.EffectiveUntil,
			SuspendedTripIDs: suspended,
		}
		logger.Info("advisory applied",
			"advisory", signal.AdvisoryID, "severity", signal.Severity,
			"route", input.RouteReference, "suspended", len(suspended))
		return nil
	}

	idleDeadline := workflow.Now(ctx).Add(routeAdvisoryIdleTimeout)
	for {
		// Expire advisories whose window has closed (auto-resume).
		now := workflow.Now(ctx)
		expired := make([]string, 0)
		for advisoryID, advisory := range active {
			if !advisory.EffectiveUntil.After(now) {
				expired = append(expired, advisoryID)
			}
		}
		sort.Strings(expired)
		for _, advisoryID := range expired {
			logger.Info("advisory window expired; resuming departures", "advisory", advisoryID)
			if err := resume(advisoryID, "metocean-expiry-"+advisoryID); err != nil {
				return RouteAdvisoryResult{}, err
			}
		}
		// With no active advisories the workflow exits after the idle
		// timeout; while advisories are active it wakes at the earliest
		// window expiry (the idle timer only runs when nothing is active, so
		// a long advisory never spins the loop on a past idle deadline).
		var wake time.Time
		if len(active) == 0 {
			if !now.Before(idleDeadline) {
				return RouteAdvisoryResult{RouteReference: input.RouteReference, Processed: processed}, nil
			}
			wake = idleDeadline
		} else {
			for _, advisory := range active {
				if wake.IsZero() || advisory.EffectiveUntil.Before(wake) {
					wake = advisory.EffectiveUntil
				}
			}
		}
		timerContext, cancelTimer := workflow.WithCancel(ctx)
		timer := workflow.NewTimer(timerContext, wake.Sub(now))

		received := false
		var signalErr error
		selector := workflow.NewSelector(ctx)
		selector.AddReceive(signalChannel, func(channel workflow.ReceiveChannel, _ bool) {
			var signal RouteAdvisorySignal
			channel.Receive(ctx, &signal)
			received = true
			signalErr = handleSignal(signal)
		})
		selector.AddFuture(timer, func(future workflow.Future) { _ = future.Get(ctx, nil) })
		selector.Select(ctx)
		cancelTimer()
		if signalErr != nil {
			return RouteAdvisoryResult{}, signalErr
		}
		if received {
			idleDeadline = workflow.Now(ctx).Add(routeAdvisoryIdleTimeout)
		}
	}
}
