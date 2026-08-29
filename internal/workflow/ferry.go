// Package workflow implements the Temporal-orchestrated FerryTicketWorkflow:
// ticket issued -> manifest update awaited -> AIS/telemetry awaited, with
// adverse-weather signals pausing boarding within 30 minutes of departure and
// emitting an AdverseWeatherAlert to the NIMASA topic. All durable side
// effects run as activities; the workflow fails closed on any contradiction.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/workflow"
)

const (
	// SignalManifestSubmitted carries the manifest submission for the trip.
	SignalManifestSubmitted = "ferry.manifest-submitted"
	// SignalTelemetryUpdated carries an AIS/telemetry update reference.
	SignalTelemetryUpdated = "ferry.telemetry-updated"
	// SignalAdverseWeather carries an authoritative adverse-weather alert.
	SignalAdverseWeather = "ferry.adverse-weather"

	// QueryStatus returns the current workflow status for observer replay.
	QueryStatus = "ferry.status"

	// ActivityPauseBoarding flips the trip to BOARDING_PAUSED.
	ActivityPauseBoarding = "ferry.pause-boarding"
	// ActivityMarkTripDeparted persists the DEPARTED trip lifecycle state at
	// the departure instant (the DB row is the historical record; the
	// workflow phase is in-memory only).
	ActivityMarkTripDeparted = "ferry.mark-trip-departed"
	// ActivityEmitWeatherAlert writes the AdverseWeatherAlert outbox event
	// bound for the NIMASA topic (ferries.manifest.v1).
	ActivityEmitWeatherAlert = "ferry.emit-adverse-weather-alert"
	// ActivityRecordManifestIncomplete records a departure without the
	// manifest (fail-closed audit trail).
	ActivityRecordManifestIncomplete = "ferry.record-manifest-incomplete"

	// adverseWeatherWindow is the pre-departure window during which an
	// adverse-weather signal pauses boarding.
	adverseWeatherWindow = 30 * time.Minute
)

// Phases reported by QueryStatus.
const (
	PhaseTicketIssued    = "TICKET_ISSUED"
	PhaseBoardingPaused  = "BOARDING_PAUSED"
	PhaseReadyToDepart   = "READY_TO_DEPART"
	PhaseDeparted        = "DEPARTED"
	PhaseManifestMissing = "MANIFEST_MISSING"
)

// Input starts one FerryTicketWorkflow.
type Input struct {
	TicketID        string    `json:"ticket_id"`
	TripID          string    `json:"trip_id"`
	VesselReference string    `json:"vessel_reference"`
	RouteReference  string    `json:"route_reference"`
	DepartureAt     time.Time `json:"departure_at"`
	CorrelationID   string    `json:"correlation_id"`
}

// Validate fails closed on any malformed input.
func (input Input) Validate() error {
	if input.TicketID == "" || input.TripID == "" || input.VesselReference == "" || input.RouteReference == "" {
		return errors.New("ticket, trip, vessel and route references are required")
	}
	if input.DepartureAt.IsZero() {
		return errors.New("departure time is required")
	}
	if input.CorrelationID == "" {
		return errors.New("correlation id is required")
	}
	return nil
}

// ManifestSignal acknowledges the NIMASA manifest submission.
type ManifestSignal struct {
	ManifestID           string `json:"manifest_id"`
	ManifestDigestSHA256 string `json:"manifest_digest_sha256"`
	PassengerCount       int    `json:"passenger_count"`
}

// TelemetrySignal carries the minimised telemetry reference (raw position
// streams never enter the workflow).
type TelemetrySignal struct {
	TelemetryReference  string    `json:"telemetry_reference"`
	PayloadDigestSHA256 string    `json:"payload_digest_sha256"`
	ObservedAt          time.Time `json:"observed_at"`
}

// AdverseWeatherSignal carries the authoritative weather alert.
type AdverseWeatherSignal struct {
	AlertID           string    `json:"alert_id"`
	Severity          string    `json:"severity"`
	PhenomenonCode    string    `json:"phenomenon_code"`
	EffectiveFrom     time.Time `json:"effective_from"`
	EffectiveUntil    time.Time `json:"effective_until"`
	BulletinReference string    `json:"bulletin_reference"`
}

// Status is the queryable workflow state.
type Status struct {
	Phase             string                 `json:"phase"`
	ManifestReceived  bool                   `json:"manifest_received"`
	TelemetryReceived bool                   `json:"telemetry_received"`
	BoardingPaused    bool                   `json:"boarding_paused"`
	Alerts            []AdverseWeatherSignal `json:"alerts"`
}

// Result reports the terminal workflow outcome.
type Result struct {
	TicketID string `json:"ticket_id"`
	TripID   string `json:"trip_id"`
	Phase    string `json:"phase"`
}

// Activities groups the durable side effects the workflow invokes. Each field
// maps to a Temporal activity implemented against PostgreSQL in production
// and mocked in tests.
type Activities struct {
	// PauseBoarding flips the trip to BOARDING_PAUSED.
	PauseBoarding func(ctx context.Context, tripID string) error
	// MarkTripDeparted persists the DEPARTED trip status at the departure
	// instant (idempotent: activities retry).
	MarkTripDeparted func(ctx context.Context, tripID string) error
	// EmitWeatherAlert records the AdverseWeatherAlert outbox event for the
	// NIMASA topic.
	EmitWeatherAlert func(ctx context.Context, tripID, routeReference string, alert AdverseWeatherSignal, correlationID string) error
	// RecordManifestIncomplete audits a departure without a manifest.
	RecordManifestIncomplete func(ctx context.Context, tripID, correlationID string) error
}

// FerryWorkflow binds the workflow definition to its activity dependencies.
// Activities are carried on the struct because workflow arguments must be
// serializable and function values are not.
type FerryWorkflow struct{ activities *Activities }

// NewFerryWorkflow fails closed when activities are absent.
func NewFerryWorkflow(activities *Activities) (*FerryWorkflow, error) {
	if activities == nil || activities.PauseBoarding == nil || activities.MarkTripDeparted == nil || activities.EmitWeatherAlert == nil || activities.RecordManifestIncomplete == nil {
		return nil, errors.New("ferry workflow activities are required")
	}
	return &FerryWorkflow{activities: activities}, nil
}

// FerryTicketWorkflow drives one issued ticket's trip from issuance to
// departure: it awaits the manifest-submitted and telemetry-updated signals
// and monitors adverse-weather signals for the whole pre-departure window.
// Adverse weather always emits an alert to the NIMASA topic; within 30
// minutes of departure it additionally pauses boarding. Departure without
// the manifest fails closed.
func (definition *FerryWorkflow) FerryTicketWorkflow(ctx workflow.Context, input Input) (Result, error) {
	if err := input.Validate(); err != nil {
		return Result{}, err
	}
	status := Status{Phase: PhaseTicketIssued, Alerts: make([]AdverseWeatherSignal, 0)}
	if err := workflow.SetQueryHandler(ctx, QueryStatus, func() (Status, error) { return status, nil }); err != nil {
		return Result{}, fmt.Errorf("register status query: %w", err)
	}

	options := workflow.ActivityOptions{StartToCloseTimeout: 2 * time.Minute}
	actx := workflow.WithActivityOptions(ctx, options)

	manifestChannel := workflow.GetSignalChannel(ctx, SignalManifestSubmitted)
	telemetryChannel := workflow.GetSignalChannel(ctx, SignalTelemetryUpdated)
	weatherChannel := workflow.GetSignalChannel(ctx, SignalAdverseWeather)

	departureIn := input.DepartureAt.Sub(workflow.Now(ctx))
	if departureIn < 0 {
		// Departure already passed: fire immediately and fail closed.
		departureIn = 0
	}
	departureTimer := workflow.NewTimer(ctx, departureIn)
	windowStart := input.DepartureAt.Add(-adverseWeatherWindow)

	selector := workflow.NewSelector(ctx)
	selector.AddReceive(manifestChannel, func(channel workflow.ReceiveChannel, _ bool) {
		var signal ManifestSignal
		channel.Receive(ctx, &signal)
		if signal.ManifestID == "" || signal.ManifestDigestSHA256 == "" {
			// Fail closed: a malformed manifest signal never marks readiness.
			return
		}
		status.ManifestReceived = true
	})
	selector.AddReceive(telemetryChannel, func(channel workflow.ReceiveChannel, _ bool) {
		var signal TelemetrySignal
		channel.Receive(ctx, &signal)
		if signal.TelemetryReference == "" || signal.PayloadDigestSHA256 == "" {
			return
		}
		status.TelemetryReceived = true
	})
	selector.AddReceive(weatherChannel, func(channel workflow.ReceiveChannel, _ bool) {
		var signal AdverseWeatherSignal
		channel.Receive(ctx, &signal)
		if signal.AlertID == "" || signal.PhenomenonCode == "" {
			return
		}
		status.Alerts = append(status.Alerts, signal)
		// Always notify NIMASA; pause boarding only inside the window.
		_ = workflow.ExecuteActivity(actx, ActivityEmitWeatherAlert, input.TripID, input.RouteReference, signal, input.CorrelationID).Get(actx, nil)
		now := workflow.Now(ctx)
		if !now.Before(windowStart) && !now.After(input.DepartureAt) && !status.BoardingPaused {
			if err := workflow.ExecuteActivity(actx, ActivityPauseBoarding, input.TripID).Get(actx, nil); err == nil {
				status.BoardingPaused = true
				status.Phase = PhaseBoardingPaused
			}
		}
	})
	departed := false
	selector.AddFuture(departureTimer, func(future workflow.Future) {
		_ = future.Get(ctx, nil)
		departed = true
	})

	// Monitor signals until the departure time: manifest and telemetry
	// readiness accumulate, adverse weather alerts emit throughout, and
	// boarding pauses inside the 30-minute window.
	for !departed {
		selector.Select(ctx)
	}

	// The departure instant is reached: persist the DEPARTED lifecycle
	// state before any terminal evaluation so historical trips never claim
	// SCHEDULED forever. The activity is idempotent; a failure retries via
	// the workflow error path.
	if err := workflow.ExecuteActivity(actx, ActivityMarkTripDeparted, input.TripID).Get(actx, nil); err != nil {
		return Result{}, fmt.Errorf("mark trip %s departed: %w", input.TripID, err)
	}

	if !status.ManifestReceived {
		// Departure without a manifest: fail closed with an audit record.
		status.Phase = PhaseManifestMissing
		if err := workflow.ExecuteActivity(actx, ActivityRecordManifestIncomplete, input.TripID, input.CorrelationID).Get(actx, nil); err != nil {
			return Result{}, fmt.Errorf("record incomplete manifest for trip %s: %w", input.TripID, err)
		}
		return Result{TicketID: input.TicketID, TripID: input.TripID, Phase: status.Phase},
			fmt.Errorf("trip %s departed without a submitted manifest", input.TripID)
	}
	if status.BoardingPaused {
		status.Phase = PhaseBoardingPaused
	} else if status.TelemetryReceived {
		status.Phase = PhaseDeparted
	} else {
		status.Phase = PhaseReadyToDepart
	}
	return Result{TicketID: input.TicketID, TripID: input.TripID, Phase: status.Phase}, nil
}
