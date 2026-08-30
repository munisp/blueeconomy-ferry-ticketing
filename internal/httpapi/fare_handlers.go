package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/fare"
)

// tracer returns the HTTP-surface tracer. With telemetry disabled the global
// provider is a no-op and spans are non-recording.
func tracer() trace.Tracer {
	return otel.Tracer("github.com/munisp/blueeconomy-ferry-ticketing/internal/httpapi")
}

// RoleConductor authenticates conductor store-and-forward uploads at the
// service level (device-management plane is TODO W-FEAT-3).
const RoleConductor = "conductor"

// FareRoutes wires the BlueFare services into the HTTP surface.
type FareRoutes struct {
	Passes     *fare.PassService
	Journeys   *fare.JourneyService
	Validation *fare.ValidationService
	Conductor  *fare.ConductorService
	Accounts   *fare.AccountService
	Settlement *fare.SettlementService
	Store      *fare.PostgresStore
}

// RegisterFareRoutes mounts the BlueFare endpoints. Every service is
// required: a partially wired fare surface fails closed at startup rather
// than serving disconnected paths.
func (server *Server) RegisterFareRoutes(authenticator auth.Authenticator, routes FareRoutes) error {
	if routes.Passes == nil || routes.Journeys == nil || routes.Validation == nil ||
		routes.Conductor == nil || routes.Accounts == nil || routes.Settlement == nil || routes.Store == nil {
		return errors.New("all BlueFare services are required (fail-closed: no partial fare surface)")
	}
	server.fare = routes
	protected := func(handler http.Handler, roles ...string) http.Handler {
		return auth.Middleware(authenticator, auth.RequireRoles(handler, roles...))
	}
	server.mux.Handle("POST /v1/fare/pass-products", protected(http.HandlerFunc(server.createPassProduct), RoleOperator, RoleStateOfficer))
	server.mux.Handle("GET /v1/fare/pass-products", protected(http.HandlerFunc(server.listPassProducts),
		RolePassenger, RoleAgentCashier, RoleOperator, RoleStateOfficer, RoleGate, RoleConductor))
	server.mux.Handle("POST /v1/fare/passes", protected(http.HandlerFunc(server.purchasePass), RolePassenger, RoleAgentCashier))
	server.mux.Handle("GET /v1/fare/passes/{id}", protected(http.HandlerFunc(server.getPass),
		RolePassenger, RoleAgentCashier, RoleOperator, RoleStateOfficer, RoleGate, RoleConductor,
		RoleNIWAOfficer, RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight))
	server.mux.Handle("GET /v1/fare/passes/{id}/artifact", protected(http.HandlerFunc(server.getPassArtifact),
		RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("POST /v1/fare/passes/{id}/{action}", protected(http.HandlerFunc(server.transitionPass), RoleOperator, RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/passes/validate", protected(http.HandlerFunc(server.validatePass), RoleOperator, RoleGate, RoleConductor))
	server.mux.Handle("GET /v1/fare/passes/validation-keys", protected(http.HandlerFunc(server.getPassValidationKeys), RoleOperator, RoleGate, RoleConductor))
	server.mux.Handle("GET /v1/fare/passes/blocklist", protected(http.HandlerFunc(server.getPassBlocklist), RoleOperator, RoleGate, RoleConductor))

	server.mux.Handle("POST /v1/fare/journeys", protected(http.HandlerFunc(server.purchaseJourney), RolePassenger, RoleAgentCashier))

	server.mux.Handle("POST /v1/fare/accounts", protected(http.HandlerFunc(server.openFareAccount), RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("GET /v1/fare/accounts/{id}", protected(http.HandlerFunc(server.getFareAccount),
		RolePassenger, RoleAgentCashier, RoleOperator, RoleNIWAOfficer, RoleStateOfficer,
		RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight))
	server.mux.Handle("POST /v1/fare/accounts/{id}/instruments", protected(http.HandlerFunc(server.registerInstrument), RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("POST /v1/fare/accounts/{id}/tap-instruments", protected(http.HandlerFunc(server.registerTapInstrument), RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("POST /v1/fare/accounts/{id}/topups", protected(http.HandlerFunc(server.topUpAccount), RolePassenger, RoleAgentCashier, RoleOperator))
	server.mux.Handle("GET /v1/fare/accounts/{id}/topups/{topupId}", protected(http.HandlerFunc(server.getTopUp),
		RolePassenger, RoleAgentCashier, RoleOperator, RoleStateOfficer, RoleIndependentAuditor, RoleAuditor))
	server.mux.Handle("GET /v1/fare/accounts/{id}/topups/{topupId}/nqr", protected(http.HandlerFunc(server.getTopUpNQR), RolePassenger, RoleAgentCashier, RoleOperator))
	// The rail webhook is HMAC-authenticated, not JWT: rails hold no service
	// tokens. Signature verification inside the handler fails closed.
	server.mux.HandleFunc("POST /v1/fare/topups/webhook", server.railWebhook)

	server.mux.Handle("POST /v1/fare/accounts/{id}/refunds", protected(http.HandlerFunc(server.requestAccountRefund), RoleOperator, RoleStateOfficer, RoleAgentCashier))
	server.mux.Handle("POST /v1/fare/refunds/{refundId}/approve", protected(http.HandlerFunc(server.approveAccountRefund), RoleOperator, RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/refunds/{refundId}/reject", protected(http.HandlerFunc(server.rejectAccountRefund), RoleOperator, RoleStateOfficer))
	server.mux.Handle("GET /v1/fare/refunds/{refundId}", protected(http.HandlerFunc(server.getAccountRefund), RoleOperator, RoleStateOfficer, RolePassenger, RoleAgentCashier))

	server.mux.Handle("POST /v1/fare/conductor/batches", protected(http.HandlerFunc(server.submitConductorBatch), RoleConductor))
	server.mux.Handle("GET /v1/fare/conductor/batches/{deviceId}/{batchId}", protected(http.HandlerFunc(server.getConductorBatch), RoleConductor, RoleOperator, RoleStateOfficer))

	server.mux.Handle("POST /v1/fare/cap-rules", protected(http.HandlerFunc(server.createCapRule), RoleOperator, RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/rules", protected(http.HandlerFunc(server.createFareRule), RoleOperator, RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/device-caps", protected(http.HandlerFunc(server.setDeviceCaps), RoleOperator, RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/settlement-rules", protected(http.HandlerFunc(server.setSettlementRule), RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/settlements/run", protected(http.HandlerFunc(server.runSettlement), RoleStateOfficer))
	server.mux.Handle("POST /v1/fare/best-fare/settle", protected(http.HandlerFunc(server.settleBestFare), RoleStateOfficer))
	server.mux.Handle("GET /v1/reports/settlement", protected(http.HandlerFunc(server.settlementReport),
		RoleOperator, RoleStateOfficer, RoleNIWAOfficer, RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight))
	server.mux.Handle("GET /v1/reports/subsidy", protected(http.HandlerFunc(server.subsidyReport),
		RoleOperator, RoleStateOfficer, RoleNIWAOfficer, RoleNIMASAObserver, RoleIndependentAuditor, RoleAuditor, RoleFMMBEOversight))
	server.mux.Handle("GET /v1/reports/offline-debits", protected(http.HandlerFunc(server.offlineDebitReport),
		RoleOperator, RoleStateOfficer, RoleIndependentAuditor, RoleAuditor))
	return nil
}

// fareDomainError maps fare domain errors to fail-closed HTTP statuses.
func writeFareError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fare.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not found")
	case errors.Is(err, fare.ErrIdempotencyConflict):
		writeError(writer, http.StatusConflict, "idempotency key conflict")
	case errors.Is(err, fare.ErrInvalidTransition):
		writeError(writer, http.StatusConflict, "state transition is not permitted")
	case errors.Is(err, fare.ErrAccountNotActive):
		writeError(writer, http.StatusConflict, "fare account is not active")
	case errors.Is(err, fare.ErrMakerChecker):
		writeError(writer, http.StatusConflict, "maker and checker must be distinct")
	case errors.Is(err, fare.ErrWebhookSignature):
		writeError(writer, http.StatusUnauthorized, "webhook signature is invalid")
	default:
		writeError(writer, http.StatusBadRequest, "request could not be processed")
	}
}

// ---------------------------------------------------------------------------
// Pass products and passes
// ---------------------------------------------------------------------------

type passProductBody struct {
	ProductID     string `json:"productId"`
	Kind          string `json:"kind"`
	ScopeType     string `json:"scopeType"`
	ScopeRef      string `json:"scopeRef"`
	PriceNGNMinor int64  `json:"priceNgnMinor"`
	OperatorID    string `json:"operatorId"`
}

func (server *Server) createPassProduct(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body passProductBody
	if !decodeBody(writer, request, &body) {
		return
	}
	operatorID := body.OperatorID
	if resolved.HasRole(RoleOperator) && !resolved.HasRole(RoleStateOfficer) {
		// Operators create products for themselves only; ministry officers
		// may create platform (NETWORK, operator-less) products.
		if resolved.OperatorID == "" {
			writeError(writer, http.StatusForbidden, "operator scope is required")
			return
		}
		operatorID = resolved.OperatorID
	}
	product := fare.PassProduct{
		ProductID:     body.ProductID,
		Kind:          strings.ToUpper(body.Kind),
		ScopeType:     strings.ToUpper(body.ScopeType),
		ScopeRef:      body.ScopeRef,
		PriceNGNMinor: body.PriceNGNMinor,
		OperatorID:    operatorID,
		Active:        true,
	}
	if product.ProductID == "" {
		product.ProductID = uuid.NewString()
	}
	if err := server.fare.Passes.CreatePassProduct(request.Context(), product); err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, product)
}

func (server *Server) listPassProducts(writer http.ResponseWriter, request *http.Request) {
	products, err := server.fare.Store.ListPassProducts(request.Context(), true)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"products": products})
}

type passPurchaseBody struct {
	ProductID    string `json:"productId"`
	PassengerRef string `json:"passengerRef"`
	Channel      string `json:"channel"`
	AgentID      string `json:"agentId"`
	AccountID    string `json:"accountId"`
}

func (server *Server) purchasePass(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body passPurchaseBody
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
	pass, err := server.fare.Passes.Purchase(request.Context(), fare.PassPurchaseRequest{
		ProductID:      body.ProductID,
		PassengerRef:   body.PassengerRef,
		Channel:        strings.ToUpper(body.Channel),
		AgentID:        body.AgentID,
		AccountID:      body.AccountID,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID(request),
		Principal:      resolved.Subject,
		PrincipalRole:  role,
	})
	if err != nil {
		server.logger.Warn("pass purchase rejected", "product_id", body.ProductID, "error", err.Error())
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, passView(pass))
}

func passView(pass fare.Pass) map[string]any {
	return map[string]any{
		"passId":    pass.PassID,
		"productId": pass.ProductID,
		"status":    pass.Status,
		"validFrom": pass.ValidFrom,
		"validTo":   pass.ValidTo,
		"purchaseId": pass.PurchaseID,
		"version":   pass.Version,
	}
}

// passReadable enforces owner / operator / oversight on pass reads.
func (server *Server) passReadable(writer http.ResponseWriter, request *http.Request, passID string) bool {
	resolved, ok := principal(writer, request)
	if !ok {
		return false
	}
	owner, err := server.fare.Store.GetPassOwnerPrincipal(request.Context(), passID)
	if err != nil {
		writeFareError(writer, err)
		return false
	}
	if owner == resolved.Subject || requireRole(resolved, oversightRoles...) || resolved.HasRole(RoleOperator) || resolved.HasRole(RoleGate) || resolved.HasRole(RoleConductor) {
		return true
	}
	writeError(writer, http.StatusForbidden, "forbidden")
	return false
}

func (server *Server) getPass(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	passID := request.PathValue("id")
	if !server.passReadable(writer, request, passID) {
		return
	}
	pass, err := server.fare.Store.GetPass(request.Context(), passID)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, passView(pass))
}

func (server *Server) getPassArtifact(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	passID := request.PathValue("id")
	if !server.passReadable(writer, request, passID) {
		return
	}
	artifact, err := server.fare.Validation.MintArtifact(request.Context(), passID)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"artifact": artifact, "passId": passID})
}

func (server *Server) transitionPass(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	passID := request.PathValue("id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeBody(writer, request, &body)
	var (
		pass fare.Pass
		err  error
	)
	switch request.PathValue("action") {
	case "revoke":
		pass, err = server.fare.Passes.Revoke(request.Context(), passID, resolved.Subject, body.Reason, correlationID(request))
	case "suspend":
		pass, err = server.fare.Passes.Suspend(request.Context(), passID, resolved.Subject, correlationID(request))
	case "unsuspend":
		pass, err = server.fare.Passes.Unsuspend(request.Context(), passID, resolved.Subject, correlationID(request))
	default:
		writeError(writer, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, passView(pass))
}

type validatePassBody struct {
	Artifact       string `json:"artifact"`
	RouteReference string `json:"routeReference"`
}

// validatePass is the online validation endpoint mirroring the offline
// device decision: ADMIT/DENY plus a PII-free reason.
func (server *Server) validatePass(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	var body validatePassBody
	if !decodeBody(writer, request, &body) {
		return
	}
	decision := server.fare.Validation.Validate(request.Context(), body.Artifact, body.RouteReference)
	writeJSON(writer, http.StatusOK, decision)
}

func (server *Server) getPassValidationKeys(writer http.ResponseWriter, request *http.Request) {
	keys, err := server.fare.Validation.ValidationKeys(request.Context())
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"keys": keys})
}

func (server *Server) getPassBlocklist(writer http.ResponseWriter, request *http.Request) {
	cursor := request.URL.Query().Get("since")
	limit := 200
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "limit must be an integer")
			return
		}
		limit = parsed
	}
	page, err := server.fare.Validation.BlocklistDelta(request.Context(), cursor, limit)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

// ---------------------------------------------------------------------------
// Capped journeys
// ---------------------------------------------------------------------------

type journeyPurchaseBody struct {
	TripID       string `json:"tripId"`
	PassengerRef string `json:"passengerRef"`
	Channel      string `json:"channel"`
	AgentID      string `json:"agentId"`
	AccountID    string `json:"accountId"`
}

func (server *Server) purchaseJourney(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body journeyPurchaseBody
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
	ticket, journey, err := server.fare.Journeys.Purchase(request.Context(), fare.JourneyPurchaseRequest{
		TripID:         body.TripID,
		PassengerRef:   body.PassengerRef,
		Channel:        strings.ToUpper(body.Channel),
		AgentID:        body.AgentID,
		AccountID:      body.AccountID,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID(request),
		Principal:      resolved.Subject,
		PrincipalRole:  role,
	})
	if err != nil {
		server.logger.Warn("journey purchase rejected", "trip_id", body.TripID, "error", err.Error())
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"ticket":  ticketView(ticket),
		"pricing": journey,
	})
}

// ---------------------------------------------------------------------------
// BlueFare accounts, instruments, top-ups
// ---------------------------------------------------------------------------

type openAccountBody struct {
	OwnerRef             string `json:"ownerRef"`
	ConcessionClass      string `json:"concessionClass"`
	ConcessionReference  string `json:"concessionReference"`
}

func (server *Server) openFareAccount(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body openAccountBody
	if !decodeBody(writer, request, &body) {
		return
	}
	ownerRef := strings.TrimSpace(body.OwnerRef)
	if ownerRef == "" {
		ownerRef = resolved.Subject
	}
	// Passengers open accounts for themselves; agents/operators may open on
	// behalf of an owner.
	if ownerRef != resolved.Subject && !requireRole(resolved, RoleOperator, RoleAgentCashier) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	account, err := server.fare.Accounts.OpenAccount(request.Context(), ownerRef,
		strings.ToUpper(body.ConcessionClass), body.ConcessionReference, resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, account)
}

// accountReadable enforces owner / operator / oversight on account reads.
func (server *Server) accountReadable(writer http.ResponseWriter, request *http.Request, accountID string) (fare.FareAccount, bool) {
	resolved, ok := principal(writer, request)
	if !ok {
		return fare.FareAccount{}, false
	}
	account, err := server.fare.Store.GetFareAccount(request.Context(), accountID)
	if err != nil {
		writeFareError(writer, err)
		return fare.FareAccount{}, false
	}
	if account.OwnerRef == resolved.Subject || requireRole(resolved, oversightRoles...) || resolved.HasRole(RoleOperator) || resolved.HasRole(RoleAgentCashier) {
		return account, true
	}
	writeError(writer, http.StatusForbidden, "forbidden")
	return fare.FareAccount{}, false
}

func (server *Server) getFareAccount(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	accountID := request.PathValue("id")
	if _, ok := server.accountReadable(writer, request, accountID); !ok {
		return
	}
	view, err := server.fare.Accounts.GetAccountView(request.Context(), accountID)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

type instrumentBody struct {
	Kind     string `json:"kind"`
	TokenRef string `json:"tokenRef"`
}

func (server *Server) registerInstrument(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	accountID := request.PathValue("id")
	if _, ok := server.accountReadable(writer, request, accountID); !ok {
		return
	}
	var body instrumentBody
	if !decodeBody(writer, request, &body) {
		return
	}
	instrument, err := server.fare.Accounts.RegisterInstrument(request.Context(), accountID,
		strings.ToUpper(body.Kind), body.TokenRef, resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, instrument)
}

type tapInstrumentBody struct {
	TokenRef     string `json:"tokenRef"`
	PublicKeyHex string `json:"publicKeyHex"`
}

// registerTapInstrument enrolls one NFC tap instrument (PRA-133).
func (server *Server) registerTapInstrument(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	accountID := request.PathValue("id")
	if _, ok := server.accountReadable(writer, request, accountID); !ok {
		return
	}
	var body tapInstrumentBody
	if !decodeBody(writer, request, &body) {
		return
	}
	instrument, err := server.fare.Accounts.RegisterTapInstrument(request.Context(), accountID,
		body.TokenRef, body.PublicKeyHex, resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, instrument)
}

type topUpBody struct {
	Channel        string `json:"channel"`
	AmountNGNMinor int64  `json:"amountNgnMinor"`
	AgentID        string `json:"agentId"`
}

func (server *Server) topUpAccount(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	accountID := request.PathValue("id")
	if _, ok := server.accountReadable(writer, request, accountID); !ok {
		return
	}
	var body topUpBody
	if !decodeBody(writer, request, &body) {
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeError(writer, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	topup, err := server.fare.Accounts.TopUp(request.Context(), fare.TopUpRequest{
		AccountID:      accountID,
		Channel:        strings.ToUpper(body.Channel),
		AmountNGNMinor: body.AmountNGNMinor,
		AgentID:        body.AgentID,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID(request),
		Principal:      resolved.Subject,
	})
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, topup)
}

func (server *Server) getTopUp(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	if _, ok := server.accountReadable(writer, request, request.PathValue("id")); !ok {
		return
	}
	topup, err := server.fare.Store.GetTopUp(request.Context(), request.PathValue("topupId"))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, topup)
}

// getTopUpNQR renders the NQR EMV payer-scan payload for a pending NQR top-up.
func (server *Server) getTopUpNQR(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	if _, ok := server.accountReadable(writer, request, request.PathValue("id")); !ok {
		return
	}
	topup, err := server.fare.Store.GetTopUp(request.Context(), request.PathValue("topupId"))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	payload, err := fare.NQRPayload(topup, "BLUEFARE TOPUP")
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"nqrPayload": payload, "reference": topup.Reference})
}

// railWebhook receives verified rail callbacks (HMAC-authenticated, not
// JWT): the ONLY path that credits rail-channel top-ups.
// ---------------------------------------------------------------------------
// Account refunds (PRA-136): maker requests, distinct checker approves or
// rejects, settlement moves value to the fare account exactly once.
// ---------------------------------------------------------------------------

type accountRefundBody struct {
	AmountMinor int64  `json:"amountNgnMinor"`
	Reason      string `json:"reason"`
}

func (server *Server) requestAccountRefund(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	accountID := request.PathValue("id")
	if _, ok := server.accountReadable(writer, request, accountID); !ok {
		return
	}
	var body accountRefundBody
	if !decodeBody(writer, request, &body) {
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		writeError(writer, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	refund, err := server.fare.Accounts.RequestAccountRefund(request.Context(), fare.AccountRefundRequest{
		AccountID:      accountID,
		AmountMinor:    body.AmountMinor,
		Reason:         body.Reason,
		IdempotencyKey: idempotencyKey,
		CorrelationID:  correlationID(request),
		Principal:      resolved.Subject,
	})
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, refund)
}

func (server *Server) approveAccountRefund(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	refund, err := server.fare.Accounts.ApproveAccountRefund(request.Context(),
		request.PathValue("refundId"), resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, refund)
}

func (server *Server) rejectAccountRefund(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	refund, err := server.fare.Accounts.RejectAccountRefund(request.Context(),
		request.PathValue("refundId"), resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, refund)
}

func (server *Server) getAccountRefund(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	refund, err := server.fare.Store.GetAccountRefund(request.Context(), request.PathValue("refundId"))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, refund)
}

func (server *Server) railWebhook(writer http.ResponseWriter, request *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1<<20))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "request body is invalid")
		return
	}
	// Top-up webhook HMAC verify span: the authentication boundary of the
	// only rail-credit path is always traced.
	_, verifySpan := tracer().Start(request.Context(), "ferry.topup_webhook.hmac_verify")
	err = server.fare.Accounts.VerifyWebhookSignature(raw, request.Header.Get("X-Rail-Signature"))
	verifySpan.End()
	if err != nil {
		writeFareError(writer, err)
		return
	}
	var webhook fare.RailWebhook
	if err := json.Unmarshal(raw, &webhook); err != nil {
		writeError(writer, http.StatusBadRequest, "request body is invalid")
		return
	}
	topup, err := server.fare.Accounts.HandleRailWebhook(request.Context(), webhook, correlationID(request))
	if err != nil {
		server.logger.Warn("rail webhook rejected", "reference", webhook.Reference, "error", err.Error())
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, topup)
}

// ---------------------------------------------------------------------------
// Conductor store-and-forward
// ---------------------------------------------------------------------------

type conductorBatchBody struct {
	DeviceID       string           `json:"deviceId"`
	BatchID        string           `json:"batchId"`
	BatchSignature string           `json:"batchSignature"`
	Scans          []fare.BatchScan `json:"scans"`
}

func (server *Server) submitConductorBatch(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body conductorBatchBody
	if !decodeBody(writer, request, &body) {
		return
	}
	operatorID := resolved.OperatorID
	if operatorID == "" {
		writeError(writer, http.StatusForbidden, "operator scope is required")
		return
	}
	result, err := server.fare.Conductor.SubmitBatch(request.Context(), fare.BatchRequest{
		DeviceID:       body.DeviceID,
		BatchID:        body.BatchID,
		OperatorID:     operatorID,
		BatchSignature: body.BatchSignature,
		Scans:          body.Scans,
		Principal:      resolved.Subject,
		CorrelationID:  correlationID(request),
	})
	if err != nil {
		server.logger.Warn("conductor batch rejected", "device_id", body.DeviceID, "batch_id", body.BatchID, "error", err.Error())
		writeFareError(writer, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, result)
}

func (server *Server) getConductorBatch(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	batch, err := server.fare.Store.GetConductorBatch(request.Context(), request.PathValue("deviceId"), request.PathValue("batchId"))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	if resolved.HasRole(RoleConductor) && !resolved.HasRole(RoleOperator) && batch.OperatorID != resolved.OperatorID {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	scans, err := server.fare.Store.ListScans(request.Context(), batch.DeviceID, batch.BatchID)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"batch": batch, "scans": scans})
}

// ---------------------------------------------------------------------------
// Rules, device caps, settlement and reports
// ---------------------------------------------------------------------------

func (server *Server) createCapRule(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body fare.CapRule
	if !decodeBody(writer, request, &body) {
		return
	}
	body.PeriodKind = strings.ToUpper(body.PeriodKind)
	body.ScopeType = strings.ToUpper(body.ScopeType)
	if resolved.HasRole(RoleOperator) && !resolved.HasRole(RoleStateOfficer) {
		if resolved.OperatorID == "" {
			writeError(writer, http.StatusForbidden, "operator scope is required")
			return
		}
		body.OperatorID = resolved.OperatorID
	}
	if body.RuleID == "" {
		body.RuleID = uuid.NewString()
	}
	body.Active = true
	if err := server.fare.Store.CreateCapRule(request.Context(), body); err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, body)
}

func (server *Server) createFareRule(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body fare.FareRule
	if !decodeBody(writer, request, &body) {
		return
	}
	body.Kind = strings.ToUpper(body.Kind)
	body.ConcessionClass = strings.ToUpper(body.ConcessionClass)
	if resolved.HasRole(RoleOperator) && !resolved.HasRole(RoleStateOfficer) {
		if resolved.OperatorID == "" {
			writeError(writer, http.StatusForbidden, "operator scope is required")
			return
		}
		body.OperatorID = resolved.OperatorID
	}
	if body.RuleID == "" {
		body.RuleID = uuid.NewString()
	}
	body.Active = true
	if err := server.fare.Store.CreateFareRule(request.Context(), body); err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, body)
}

func (server *Server) setDeviceCaps(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body fare.DeviceCaps
	if !decodeBody(writer, request, &body) {
		return
	}
	if body.DeviceID == "" || body.PerTxCapMinor <= 0 || body.DailyCapMinor <= 0 {
		writeError(writer, http.StatusBadRequest, "device id and positive caps are required")
		return
	}
	if resolved.HasRole(RoleOperator) && !resolved.HasRole(RoleStateOfficer) {
		if resolved.OperatorID == "" {
			writeError(writer, http.StatusForbidden, "operator scope is required")
			return
		}
		body.OperatorID = resolved.OperatorID
	}
	body.Active = true
	if err := server.fare.Store.SetDeviceCaps(request.Context(), body); err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, body)
}

func (server *Server) setSettlementRule(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	var body fare.SettlementRule
	if !decodeBody(writer, request, &body) {
		return
	}
	if body.OperatorID == "" || body.OperatorShareBps < 0 || body.OperatorShareBps > 10000 {
		writeError(writer, http.StatusBadRequest, "operator id and share basis points within 0..10000 are required")
		return
	}
	body.Active = true
	if err := server.fare.Store.UpsertSettlementRule(request.Context(), body); err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, body)
}

func periodQuery(writer http.ResponseWriter, request *http.Request) (time.Time, time.Time, bool) {
	from, err := time.Parse("2006-01-02", request.URL.Query().Get("from"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "from must be YYYY-MM-DD")
		return time.Time{}, time.Time{}, false
	}
	to, err := time.Parse("2006-01-02", request.URL.Query().Get("to"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "to must be YYYY-MM-DD")
		return time.Time{}, time.Time{}, false
	}
	return from.UTC(), to.UTC(), true
}

func (server *Server) settlementReport(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	operatorID := request.URL.Query().Get("operatorId")
	if resolved.HasRole(RoleOperator) && !requireRole(resolved, oversightRoles...) {
		operatorID = resolved.OperatorID // operators see only their own
	}
	if operatorID == "" {
		writeError(writer, http.StatusBadRequest, "operatorId is required")
		return
	}
	from, to, ok := periodQuery(writer, request)
	if !ok {
		return
	}
	report, err := server.fare.Settlement.Report(request.Context(), operatorID, from, to)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

func (server *Server) runSettlement(writer http.ResponseWriter, request *http.Request) {
	resolved, ok := principal(writer, request)
	if !ok {
		return
	}
	var body struct {
		OperatorID  string `json:"operatorId"`
		PeriodStart string `json:"periodStart"`
		PeriodEnd   string `json:"periodEnd"`
	}
	if !decodeBody(writer, request, &body) {
		return
	}
	from, err := time.Parse("2006-01-02", body.PeriodStart)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "periodStart must be YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", body.PeriodEnd)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "periodEnd must be YYYY-MM-DD")
		return
	}
	run, err := server.fare.Settlement.Run(request.Context(), body.OperatorID, from.UTC(), to.UTC(),
		resolved.Subject, correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, run)
}

func (server *Server) subsidyReport(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	from, to, ok := periodQuery(writer, request)
	if !ok {
		return
	}
	lines, err := server.fare.Settlement.Subsidy(request.Context(), from, to)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"routes": lines})
}

func (server *Server) offlineDebitReport(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	from, to, ok := periodQuery(writer, request)
	if !ok {
		return
	}
	reports, err := server.fare.Store.OfflineDebitReconciliation(request.Context(), from, to)
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"devices": reports})
}

func (server *Server) settleBestFare(writer http.ResponseWriter, request *http.Request) {
	if _, ok := principal(writer, request); !ok {
		return
	}
	var body struct {
		WeekStart string `json:"weekStart"`
	}
	if !decodeBody(writer, request, &body) {
		return
	}
	weekStart, err := time.Parse("2006-01-02", body.WeekStart)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "weekStart must be YYYY-MM-DD")
		return
	}
	settled, err := server.fare.Settlement.SettleBestFare(request.Context(), weekStart.UTC(), correlationID(request))
	if err != nil {
		writeFareError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"adjustmentsSettled": settled})
}
