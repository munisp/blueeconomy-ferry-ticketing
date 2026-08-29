// Package httpapi exposes the ferry ticketing HTTP surface: per-passenger
// purchase, the NIMASA manifest export and the operator portal. Every
// authenticated route resolves a Principal; operator routes are scoped to the
// principal's operator_id at the service/DB layer, not only at the edge.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

// Platform roles recognized by this service.
const (
	RolePassenger          = "passenger"
	RoleOperator           = "operator"
	RoleAgentCashier       = "agent-cashier"
	RoleGate               = "gate"
	RoleNIWAOfficer        = "niwa-officer"
	RoleStateOfficer       = "state-officer"
	RoleNIMASAObserver     = "nimasa-observer"
	RoleIndependentAuditor = "independent-auditor"
	RoleAuditor            = "auditor"
	RoleFMMBEOversight     = "fmmbe-oversight"
)

// oversightRoles may read manifests and tickets across operators.
var oversightRoles = []string{
	RoleNIWAOfficer, RoleStateOfficer, RoleNIMASAObserver,
	RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight,
}

// TicketService is the purchase/refund boundary.
type TicketService interface {
	Purchase(ctx context.Context, request ticketing.PurchaseRequest) (ticketing.Ticket, error)
	Refund(ctx context.Context, ticketID, principal, principalRole, correlationID string) (ticketing.Ticket, error)
	Void(ctx context.Context, ticketID, correlationID string) (ticketing.Ticket, error)
	Expire(ctx context.Context, ticketID, correlationID string) (ticketing.Ticket, error)
}

// BoardingService is the signed-artifact mint/verify/embark boundary.
type BoardingService interface {
	MintArtifact(ctx context.Context, ticketID string) (ticketing.Artifact, error)
	VerifyArtifact(ctx context.Context, token, principal, correlationID string) (ticketproof.Payload, error)
	Embark(ctx context.Context, operatorID, ticketID, artifact, principal, correlationID string) (ticketing.Ticket, error)
	// VerificationKeys exposes the public key set for offline verifiers;
	// previous is nil when no rotation is configured or the grace window
	// has expired.
	VerificationKeys() (current ticketproof.VerificationKey, previous *ticketproof.VerificationKey)
}

// OperatorStore is the operator portal persistence boundary.
type OperatorStore interface {
	CreateVessel(ctx context.Context, vessel ticketing.Vessel) error
	ListVessels(ctx context.Context, operatorID string) ([]ticketing.Vessel, error)
	GetVessel(ctx context.Context, operatorID, vesselID string) (ticketing.Vessel, error)
	UpdateVessel(ctx context.Context, vessel ticketing.Vessel) error
	DeleteVessel(ctx context.Context, operatorID, vesselID string) error
	CreateTrip(ctx context.Context, trip ticketing.Trip) error
	ListTrips(ctx context.Context, operatorID string) ([]ticketing.Trip, error)
	GetTripScoped(ctx context.Context, operatorID, tripID string) (ticketing.Trip, error)
	GetTrip(ctx context.Context, tripID string) (ticketing.Trip, error)
	GetTicket(ctx context.Context, ticketID string) (ticketing.Ticket, error)
	Dashboard(ctx context.Context, operatorID string) (ticketing.Dashboard, error)
}

// ManifestSource is the manifest persistence boundary.
type ManifestSource interface {
	ManifestTickets(ctx context.Context, tripID string) ([]ticketing.Ticket, error)
	RecordManifest(ctx context.Context, manifest manifest.Manifest, event ticketing.Event) error
	LatestManifest(ctx context.Context, tripID string) (manifest.Manifest, error)
	ManifestCompleteness(ctx context.Context, operatorID string) (int64, int64, error)
}

// Server wires the routes.
type Server struct {
	tickets   TicketService
	operator  OperatorStore
	manifests ManifestSource
	boarding  BoardingService
	salt      string
	kpi       float64
	logger    *slog.Logger
	readiness func(ctx context.Context) error
	mux       *http.ServeMux
	handler   http.Handler
}

// NewServer fails closed on any missing dependency, telemetry included.
func NewServer(authenticator auth.Authenticator, tickets TicketService, operator OperatorStore, manifests ManifestSource, boarding BoardingService, manifestSalt string, completenessKPI float64, logger *slog.Logger, readiness func(ctx context.Context) error, pipeline *telemetry.Telemetry) (*Server, error) {
	if authenticator == nil || tickets == nil || operator == nil || manifests == nil {
		return nil, errors.New("authenticator, ticket service, operator store and manifest store are required")
	}
	if boarding == nil {
		return nil, errors.New("boarding service is required (fail-closed: no unsigned boarding path)")
	}
	if len(manifestSalt) < 16 {
		return nil, errors.New("manifest salt of at least 16 characters is required")
	}
	if completenessKPI <= 0 || completenessKPI > 1 {
		return nil, errors.New("manifest completeness KPI must be within (0, 1]")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if readiness == nil {
		return nil, errors.New("readiness probe is required (fail-closed)")
	}
	if pipeline == nil {
		return nil, errors.New("telemetry pipeline is required (fail-closed); use telemetry.Setup with a disabled config for no-op tracing")
	}
	server := &Server{
		tickets: tickets, operator: operator, manifests: manifests, boarding: boarding,
		salt: manifestSalt, kpi: completenessKPI, logger: logger, readiness: readiness,
		mux: http.NewServeMux(),
	}
	server.routes(authenticator)
	server.mux.Handle("GET /metrics", pipeline.MetricsHandler())
	server.handler = pipeline.Middleware(server.mux)
	return server, nil
}

func (server *Server) routes(authenticator auth.Authenticator) {
	server.mux.HandleFunc("GET /healthz", server.healthz)
	server.mux.HandleFunc("GET /readyz", server.readyz)

	protected := func(handler http.Handler, roles ...string) http.Handler {
		return auth.Middleware(authenticator, auth.RequireRoles(handler, roles...))
	}
	server.mux.Handle("POST /v1/tickets", protected(http.HandlerFunc(server.purchaseTicket), RolePassenger, RoleAgentCashier))
	server.mux.Handle("GET /v1/tickets/{id}", protected(http.HandlerFunc(server.getTicket),
		RolePassenger, RoleAgentCashier, RoleOperator, RoleNIWAOfficer, RoleStateOfficer,
		RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight))
	server.mux.Handle("POST /v1/tickets/{id}/refund", protected(http.HandlerFunc(server.refundTicket), RolePassenger, RoleOperator))
	server.mux.Handle("POST /v1/tickets/{id}/void", protected(http.HandlerFunc(server.voidTicket), RoleOperator, RoleStateOfficer))
	server.mux.Handle("GET /v1/tickets/{id}/artifact", protected(http.HandlerFunc(server.getTicketArtifact), RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("POST /v1/tickets/verify", protected(http.HandlerFunc(server.verifyTicketArtifact), RoleOperator, RoleGate))
	// Key distribution for offline verifiers (gate scanners, the mobile
	// inspector). Authenticated like the online verify route — the keys are
	// public material, but the platform exposes no unauthenticated surface
	// beyond health/readiness.
	server.mux.Handle("GET /v1/tickets/verification-keys", protected(http.HandlerFunc(server.getVerificationKeys), RoleOperator, RoleGate))

	server.mux.Handle("GET /v1/nimasa/trips/{tripID}/manifest", protected(http.HandlerFunc(server.getManifest),
		RoleNIWAOfficer, RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleOperator, RoleStateOfficer, RoleFMMBEOversight))

	server.mux.Handle("POST /v1/operator/vessels", protected(http.HandlerFunc(server.createVessel), RoleOperator))
	server.mux.Handle("GET /v1/operator/vessels", protected(http.HandlerFunc(server.listVessels), RoleOperator))
	server.mux.Handle("GET /v1/operator/vessels/{id}", protected(http.HandlerFunc(server.getVessel), RoleOperator))
	server.mux.Handle("PATCH /v1/operator/vessels/{id}", protected(http.HandlerFunc(server.updateVessel), RoleOperator))
	server.mux.Handle("DELETE /v1/operator/vessels/{id}", protected(http.HandlerFunc(server.deleteVessel), RoleOperator))
	server.mux.Handle("POST /v1/operator/trips", protected(http.HandlerFunc(server.createTrip), RoleOperator))
	server.mux.Handle("GET /v1/operator/trips", protected(http.HandlerFunc(server.listTrips), RoleOperator))
	server.mux.Handle("POST /v1/operator/trips/{id}/manifest/export", protected(http.HandlerFunc(server.exportManifest), RoleOperator))
	server.mux.Handle("POST /v1/operator/tickets/{id}/embark", protected(http.HandlerFunc(server.embarkTicket), RoleOperator))
	server.mux.Handle("GET /v1/operator/dashboard", protected(http.HandlerFunc(server.dashboard), RoleOperator))
}

// ServeHTTP implements http.Handler.
func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.handler.ServeHTTP(writer, request)
}

func (server *Server) healthz(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) readyz(writer http.ResponseWriter, request *http.Request) {
	if err := server.readiness(request.Context()); err != nil {
		server.logger.Warn("readiness probe failed", "error", err.Error())
		writeError(writer, http.StatusServiceUnavailable, "not ready")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

// correlationID propagates or creates the correlation identifier.
func correlationID(request *http.Request) string {
	if value := strings.TrimSpace(request.Header.Get("X-Correlation-Id")); value != "" && len(value) <= 128 {
		return value
	}
	return uuid.NewString()
}

// principal resolves the authenticated principal or fails closed.
func principal(writer http.ResponseWriter, request *http.Request) (auth.Principal, bool) {
	resolved, ok := auth.PrincipalFrom(request.Context())
	if !ok {
		writeError(writer, http.StatusForbidden, "forbidden")
		return auth.Principal{}, false
	}
	return resolved, true
}

// operatorScope resolves the operator_id claim; fail-closed when absent.
func operatorScope(writer http.ResponseWriter, request *http.Request) (string, bool) {
	resolved, ok := principal(writer, request)
	if !ok {
		return "", false
	}
	if resolved.OperatorID == "" {
		writeError(writer, http.StatusForbidden, "operator scope is required")
		return "", false
	}
	trace.SpanFromContext(request.Context()).SetAttributes(attribute.String("ferry.operator_id", resolved.OperatorID))
	return resolved.OperatorID, true
}

// canReadTicket enforces ownership / operator scope / oversight at the
// service layer.
func canReadTicket(resolved auth.Principal, ticket ticketing.Ticket) bool {
	if ticket.PurchaserPrincipal == resolved.Subject {
		return true
	}
	if resolved.HasRole(RoleOperator) && resolved.OperatorID != "" && resolved.OperatorID == ticket.OperatorID {
		return true
	}
	for _, role := range oversightRoles {
		if resolved.HasRole(role) {
			return true
		}
	}
	return false
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

// writeDomainError maps domain errors to fail-closed HTTP statuses without
// leaking internals.
func writeDomainError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ticketing.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not found")
	case errors.Is(err, ticketing.ErrCapacityExceeded):
		writeError(writer, http.StatusConflict, "trip capacity is fully reserved")
	case errors.Is(err, ticketing.ErrBoardingAlreadyConsumed):
		writeError(writer, http.StatusConflict, "BOARDING_ALREADY_CONSUMED")
	case errors.Is(err, ticketing.ErrTicketProofInvalid):
		writeError(writer, http.StatusUnauthorized, "ticket artifact verification failed")
	case errors.Is(err, ticketing.ErrInvalidTransition):
		writeError(writer, http.StatusConflict, "state transition is not permitted")
	case errors.Is(err, ticketing.ErrTicketBoarded):
		writeError(writer, http.StatusConflict, "ticket boarding has been consumed; refund is not permitted")
	case errors.Is(err, ticketing.ErrIdempotencyConflict):
		writeError(writer, http.StatusConflict, "idempotency key conflict")
	default:
		writeError(writer, http.StatusBadRequest, "request could not be processed")
	}
}

func decodeBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "request body is invalid")
		return false
	}
	return true
}
