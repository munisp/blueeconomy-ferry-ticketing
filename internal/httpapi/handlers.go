package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
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
	voided, err := server.tickets.Void(request.Context(), ticket.TicketID, correlationID(request))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(voided))
}

type ticketViewBody struct {
	TicketID        string `json:"ticketId"`
	TripID          string `json:"tripId"`
	State           string `json:"state"`
	FareNGNMinor    int64  `json:"fareNgnMinor"`
	Channel         string `json:"channel"`
	SeatNumber      *int   `json:"seatNumber,omitempty"`
	PassengerDigest string `json:"passengerDigestSha256"`
	CorrelationID   string `json:"correlationId"`
	Version         int64  `json:"version"`
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
	ticket, err := server.operator.MarkEmbarked(request.Context(), operatorID, request.PathValue("id"))
	if err != nil {
		writeDomainError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticketView(ticket))
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
