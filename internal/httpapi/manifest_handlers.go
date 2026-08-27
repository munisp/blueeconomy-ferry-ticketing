package httpapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// manifestAccess enforces the NIMASA manifest access policy at the service
// layer: oversight roles read any trip; operators read only their own.
func (server *Server) manifestAccess(resolved auth.Principal, trip ticketing.Trip) bool {
	if requireRole(resolved, RoleNIWAOfficer, RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleStateOfficer, RoleFMMBEOversight) {
		return true
	}
	return resolved.HasRole(RoleOperator) && resolved.OperatorID != "" && resolved.OperatorID == trip.OperatorID
}

// getManifest exports the per-departure passenger manifest as a FHIR-aligned
// collection Bundle with anonymized passenger entries (salted digests only).
func (server *Server) getManifest(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	trip, err := server.operator.GetTrip(request.Context(), request.PathValue("tripID"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !server.manifestAccess(resolved, trip) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	bundle, record, err := server.buildManifest(request, trip, resolved)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"bundle": bundle,
		"manifest": map[string]any{
			"manifestId":         record.ManifestID,
			"passengerCount":     record.PassengerCount,
			"expectedPassengers": record.ExpectedPassengers,
			"completeness":       record.Completeness(),
			"kpi":                server.kpi,
			"meetsKpi":           record.MeetsKPI(server.kpi),
			"digestSha256":       record.DigestSHA256,
		},
	})
}

// exportManifest is the operator-triggered export: builds the bundle, persists
// the manifest record and writes the ferries.manifest.v1 outbox event in one
// transaction.
func (server *Server) exportManifest(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	trip, err := server.operator.GetTripScoped(request.Context(), operatorID, request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	bundle, record, err := server.buildManifest(request, trip, resolved)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	digest, err := manifest.Digest(bundle)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	record.DigestSHA256 = digest
	record.ExpectedPassengers = trip.SeatsReserved
	correlation := correlationID(request)
	event := ticketing.Event{
		EventID:       uuid.NewString(),
		Topic:         ticketing.TopicManifest,
		SubjectID:     record.ManifestID,
		EventType:     ticketing.EventManifestExported,
		CorrelationID: correlation,
		Payload: map[string]any{
			"manifest_id":            record.ManifestID,
			"vessel_reference":       record.VesselReference,
			"voyage_reference":       trip.TripID,
			"terminal_reference":     record.TerminalReference,
			"scheduled_departure_at": trip.ScheduledDeparture.UTC().Format(time.RFC3339),
			"passenger_count":        record.PassengerCount,
			"expected_passengers":    record.ExpectedPassengers,
			"manifest_digest_sha256": record.DigestSHA256,
			"exported_by_principal":  resolved.Subject,
			"principal_role":         RoleOperator,
		},
	}
	if err := server.manifests.RecordManifest(request.Context(), record, event); err != nil {
		writeDomainError(writer, err)
		return
	}
	server.logger.Info("manifest exported", "manifest_id", record.ManifestID, "trip_id", trip.TripID,
		"passenger_count", record.PassengerCount, "correlation_id", correlation)
	writeJSON(writer, http.StatusCreated, map[string]any{
		"manifestId":         record.ManifestID,
		"passengerCount":     record.PassengerCount,
		"expectedPassengers": record.ExpectedPassengers,
		"completeness":       record.Completeness(),
		"kpi":                server.kpi,
		"meetsKpi":           record.MeetsKPI(server.kpi),
		"digestSha256":       record.DigestSHA256,
		"bundle":             bundle,
	})
}

// buildManifest assembles the bundle and (unsigned) export record for a trip.
// passengerCount == entry count is enforced inside manifest.BuildBundle.
func (server *Server) buildManifest(request *http.Request, trip ticketing.Trip, resolved auth.Principal) (manifest.Bundle, manifest.Manifest, error) {
	tickets, err := server.manifests.ManifestTickets(request.Context(), trip.TripID)
	if err != nil {
		return manifest.Bundle{}, manifest.Manifest{}, err
	}
	manifestID := uuid.NewString()
	now := time.Now().UTC()
	bundle, _, err := manifest.BuildBundle(manifestID, trip, tickets, now)
	if err != nil {
		return manifest.Bundle{}, manifest.Manifest{}, err
	}
	record := manifest.Manifest{
		ManifestID:          manifestID,
		TripID:              trip.TripID,
		OperatorID:          trip.OperatorID,
		VesselReference:     trip.VesselID,
		TerminalReference:   trip.TerminalReference,
		ScheduledDeparture:  trip.ScheduledDeparture,
		PassengerCount:      len(tickets),
		ExpectedPassengers:  trip.SeatsReserved,
		ExportedByPrincipal: resolved.Subject,
		ExportedAt:          now,
	}
	return bundle, record, nil
}
