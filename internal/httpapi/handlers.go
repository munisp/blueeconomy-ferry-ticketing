package httpapi

import (
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

type purchaseRequestBody struct {
	TripID       string `json:"tripId"`
	PassengerRef string `json:"passengerRef"`
	Channel      string `json:"channel"`
	AgentID      string `json:"agentId"`
}

func (server *Server) purchaseTicket(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body purchaseRequestBody
	if !decodeBody(writer, request, &body) {
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeError(writer, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	role := RolePassenger
	if resolved.HasRole(RoleAgentCashier) {
		role = RoleAgentCashier
	}
	ticket, err := server.tickets.Purchase(request.Context(), ticketing.PurchaseRequest{
		TripID:         body.TripID,
		PassengerRef:   body.PassengerRef,
		Channel:        ticketing.Channel(body.Channel),
		AgentID:        body.AgentID,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID(request),
		Principal:      resolved.Subject,
		PrincipalRole:  role,
	})
	if err != nil {
		server.logger.Warn("ticket purchase rejected", "trip_id", body.TripID, "error", err.Error())
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, ticketView(ticket))
}

func (server *Server) getTicket(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if !canReadTicket(resolved, ticket) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(ticket))
}

func (server *Server) refundTicket(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	owner := ticket.PurchaserPrincipal == resolved.Subject
	operator := resolved.HasRole(RoleOperator) && resolved.OperatorID != "" && resolved.OperatorID == ticket.OperatorID
	if !owner && !operator {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	role := RolePassenger
	if operator {
		role = RoleOperator
	}
	refunded, err := server.tickets.Refund(request.Context(), ticket.TicketID, resolved.Subject, role, correlationID(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(refunded))
}

func (server *Server) voidTicket(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	if resolved.HasRole(RoleOperator) && (resolved.OperatorID == "" || resolved.OperatorID != ticket.OperatorID) && !resolved.HasRole(RoleStateOfficer) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	role := RoleOperator
	if resolved.HasRole(RoleStateOfficer) && !resolved.HasRole(RoleOperator) {
		role = RoleStateOfficer
	}
	voided, err := server.tickets.Void(request.Context(), ticket.TicketID, resolved.Subject, role, correlationID(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(voided))
}

type ticketViewBody struct {
	TicketID        string     `json:"ticketId"`
	TripID          string     `json:"tripId"`
	State           string     `json:"state"`
	FareNGNMinor    int64      `json:"fareNgnMinor"`
	Channel         string     `json:"channel"`
	SeatNumber      *int       `json:"seatNumber,omitempty"`
	PassengerDigest string     `json:"passengerDigestSha256"`
	CorrelationID   string     `json:"correlationId"`
	Version         int64      `json:"version"`
	Embarked        bool       `json:"embarked"`
	BoardedAt       *time.Time `json:"boardedAt,omitempty"`
	BoardedBy       string     `json:"boardedBy,omitempty"`
	ArtifactKid     string     `json:"artifactKid,omitempty"`
}

type embarkRequestBody struct {
	Artifact string `json:"artifact"`
}

type verifyRequestBody struct {
	Artifact string `json:"artifact"`
}

func ticketView(ticket ticketing.Ticket) ticketViewBody {
	return ticketViewBody{
		TicketID:        ticket.TicketID,
		TripID:          ticket.TripID,
		State:           string(ticket.State),
		FareNGNMinor:    ticket.FareNGNMinor,
		Channel:         string(ticket.Channel),
		SeatNumber:      ticket.SeatNumber,
		PassengerDigest: ticket.PassengerDigest,
		CorrelationID:   ticket.CorrelationID,
		Version:         ticket.Version,
		Embarked:        ticket.Embarked,
		BoardedAt:       ticket.BoardedAt,
		BoardedBy:       ticket.BoardedBy,
		ArtifactKid:     ticket.ArtifactKid,
	}
}

type vesselBody struct {
	Name      string `json:"name"`
	IMONumber string `json:"imoNumber"`
	Capacity  int    `json:"capacity"`
	Active    bool   `json:"active"`
}

func (server *Server) createVessel(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	var body vesselBody
	if !decodeBody(writer, request, &body) {
		return
	}
	vessel := ticketing.Vessel{
		VesselID:   uuid.NewString(),
		OperatorID: operatorID,
		Name:       body.Name,
		IMONumber:  body.IMONumber,
		Capacity:   body.Capacity,
		Active:     body.Active,
	}
	if err := server.operator.CreateVessel(request.Context(), vessel); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, vessel)
}

func (server *Server) listVessels(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	vessels, err := server.operator.ListVessels(request.Context(), operatorID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"vessels": vessels})
}

func (server *Server) getVessel(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	vessel, err := server.operator.GetVessel(request.Context(), operatorID, request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, vessel)
}

func (server *Server) updateVessel(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	var body vesselBody
	if !decodeBody(writer, request, &body) {
		return
	}
	vessel := ticketing.Vessel{
		VesselID:   request.PathValue("id"),
		OperatorID: operatorID,
		Name:       body.Name,
		IMONumber:  body.IMONumber,
		Capacity:   body.Capacity,
		Active:     body.Active,
	}
	if err := server.operator.UpdateVessel(request.Context(), vessel); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, vessel)
}

func (server *Server) deleteVessel(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	if err := server.operator.DeleteVessel(request.Context(), operatorID, request.PathValue("id")); err != nil {
		writeDomainError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type tripBody struct {
	VesselID           string    `json:"vesselId"`
	RouteReference     string    `json:"routeReference"`
	TerminalReference  string    `json:"terminalReference"`
	ScheduledDeparture time.Time `json:"scheduledDeparture"`
	FareNGNMinor       int64     `json:"fareNgnMinor"`
}

func (server *Server) createTrip(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	var body tripBody
	if !decodeBody(writer, request, &body) {
		return
	}
	trip := ticketing.Trip{
		TripID:             uuid.NewString(),
		VesselID:           body.VesselID,
		OperatorID:         operatorID,
		RouteReference:     body.RouteReference,
		TerminalReference:  body.TerminalReference,
		ScheduledDeparture: body.ScheduledDeparture.UTC(),
		FareNGNMinor:       body.FareNGNMinor,
	}
	if err := server.operator.CreateTrip(request.Context(), trip); err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, trip)
}

func (server *Server) listTrips(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	trips, err := server.operator.ListTrips(request.Context(), operatorID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"trips": trips})
}

func (server *Server) embarkTicket(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	resolved, _ := auth.PrincipalFrom(request.Context())
	// The signed-artifact path is the default; an empty body is the legacy
	// raw-ticket-id path, retained for backward compatibility.
	var body embarkRequestBody
	artifact := ""
	if request.Body != nil && request.ContentLength != 0 {
		if !decodeBody(writer, request, &body) {
			return
		}
		artifact = strings.TrimSpace(body.Artifact)
	}
	if artifact == "" {
		server.logger.Warn("legacy raw-ticket-id embark used; migrate gates to signed artifacts",
			"ticket_id", request.PathValue("id"), "operator_id", operatorID, "correlation_id", correlationID(request))
	}
	ticket, err := server.boarding.Embark(request.Context(), operatorID, request.PathValue("id"), artifact, resolved.Subject, correlationID(request))
	if err != nil {
		server.logger.Warn("embark rejected", "ticket_id", request.PathValue("id"), "error", err.Error())
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(ticket))
}

// getTicketArtifact mints the signed, QR-encodable boarding artifact for an
// ISSUED ticket. The artifact is a bearer capability: only the purchaser and
// the owning operator may retrieve it (no oversight roles).
func (server *Server) getTicketArtifact(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	ticket, err := server.operator.GetTicket(request.Context(), request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	owner := ticket.PurchaserPrincipal == resolved.Subject
	operator := resolved.HasRole(RoleOperator) && resolved.OperatorID != "" && resolved.OperatorID == ticket.OperatorID
	if !owner && !operator {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	artifact, err := server.boarding.MintArtifact(request.Context(), ticket.TicketID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, artifact)
}

// verifyTicketArtifact is the stateless gate check: authenticity (Ed25519
// signature, trusted kid, rotation grace, expiry) plus the rotating window
// code. No database read is required for authenticity; failures emit
// CONFIDENTIAL fraud telemetry and are logged without PII.
func (server *Server) verifyTicketArtifact(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body verifyRequestBody
	if !decodeBody(writer, request, &body) {
		return
	}
	payload, err := server.boarding.VerifyArtifact(request.Context(), strings.TrimSpace(body.Artifact), resolved.Subject, correlationID(request))
	if err != nil {
		server.logger.Warn("ticket artifact verification failed",
			"reason", strings.TrimPrefix(err.Error(), ticketing.ErrTicketProofInvalid.Error()+": "),
			"correlation_id", correlationID(request))
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"valid":         true,
		"ticketId":      payload.TicketID,
		"tripId":        payload.TripID,
		"seatNumber":    payload.Seat,
		"kid":           payload.KeyID,
		"rotationEpoch": payload.RotationEpoch,
		"expiresAt":     payload.ExpiresAt,
	})
}

// verificationKeyBody is the wire shape consumed by the mobile inspector key
// cache (blueeconomy-mobile src/core/api/fetchers.ts). Field names and types
// must stay in lockstep with that parser: kid (string), public_key_hex
// (lowercase hex of the raw 32-byte Ed25519 public key), epoch (number),
// grace_until_unix (number, null for the current key). Public material only —
// private keys and the HMAC window secret are never served.
type verificationKeyBody struct {
	KeyID          string `json:"kid"`
	Algorithm      string `json:"algorithm"`
	PublicKeyHex   string `json:"public_key_hex"`
	Epoch          uint32 `json:"epoch"`
	GraceUntilUnix *int64 `json:"grace_until_unix"`
}

func verificationKeyView(key ticketproof.VerificationKey) verificationKeyBody {
	body := verificationKeyBody{
		KeyID:        key.KeyID,
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(key.Public),
		Epoch:        key.Epoch,
	}
	if !key.GraceUntil.IsZero() {
		until := key.GraceUntil.Unix()
		body.GraceUntilUnix = &until
	}
	return body
}

// getVerificationKeys distributes the trusted public key set to offline
// verifiers: the current signing key plus the previous key while it remains
// inside its rotation grace window (`previous` is null otherwise). Verifiers
// cache the set and refresh it online; a fetch failure keeps the old cache.
func (server *Server) getVerificationKeys(writer http.ResponseWriter, _ *http.Request) {
	current, previous := server.boarding.VerificationKeys()
	response := map[string]any{"current": verificationKeyView(current)}
	if previous != nil {
		response["previous"] = verificationKeyView(*previous)
	} else {
		response["previous"] = nil
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) dashboard(writer http.ResponseWriter, request *http.Request) {
	operatorID, ok := operatorScope(writer, request)
	if !ok {
		return
	}
	dashboard, err := server.operator.Dashboard(request.Context(), operatorID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	included, expected, err := server.manifests.ManifestCompleteness(request.Context(), operatorID)
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	completeness := 1.0
	if expected > 0 {
		completeness = float64(included) / float64(expected)
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"operatorId":       dashboard.OperatorID,
		"ticketsSold":      dashboard.TicketsSold,
		"revenueNgnMinor":  dashboard.RevenueNGNMinor,
		"perCorridorStats": dashboard.PerCorridorStats,
		"manifestCompleteness": map[string]any{
			"included": included,
			"expected": expected,
			"ratio":    completeness,
			"kpi":      server.kpi,
			"meetsKpi": completeness >= server.kpi,
		},
	})
}

// requireRole helper for handlers combining roles beyond middleware scope.
func requireRole(resolved auth.Principal, roles ...string) bool {
	for _, role := range roles {
		if resolved.HasRole(role) {
			return true
		}
	}
	return false
}
