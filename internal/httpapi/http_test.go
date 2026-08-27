package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// headerAuthenticator drives the real auth middleware from test headers:
// X-Test-Subject / X-Test-Roles (comma-separated) / X-Test-Operator-Id.
// Missing subject means unauthenticated. Token verification itself is covered
// in the auth package tests.
type headerAuthenticator struct{}

func (headerAuthenticator) Authenticate(request *http.Request) (auth.Principal, error) {
	subject := strings.TrimSpace(request.Header.Get("X-Test-Subject"))
	if subject == "" {
		return auth.Principal{}, errors.New("unauthenticated")
	}
	roles := make(map[string]struct{})
	for _, role := range strings.Split(request.Header.Get("X-Test-Roles"), ",") {
		if role = strings.TrimSpace(role); role != "" {
			roles[role] = struct{}{}
		}
	}
	return auth.Principal{
		Subject:    subject,
		Roles:      roles,
		OperatorID: strings.TrimSpace(request.Header.Get("X-Test-Operator-Id")),
	}, nil
}

type fakeTicketService struct {
	purchased []ticketing.PurchaseRequest
	ticket    ticketing.Ticket
	err       error
}

func (service *fakeTicketService) Purchase(_ context.Context, request ticketing.PurchaseRequest) (ticketing.Ticket, error) {
	service.purchased = append(service.purchased, request)
	if service.err != nil {
		return ticketing.Ticket{}, service.err
	}
	return service.ticket, nil
}

func (service *fakeTicketService) Refund(_ context.Context, ticketID, principal, principalRole, correlationID string) (ticketing.Ticket, error) {
	return ticketing.Ticket{TicketID: ticketID, State: ticketing.StateRefunded}, nil
}

func (service *fakeTicketService) Void(_ context.Context, ticketID, correlationID string) (ticketing.Ticket, error) {
	return ticketing.Ticket{TicketID: ticketID, State: ticketing.StateVoid}, nil
}

func (service *fakeTicketService) Expire(_ context.Context, ticketID, correlationID string) (ticketing.Ticket, error) {
	return ticketing.Ticket{TicketID: ticketID, State: ticketing.StateExpired}, nil
}

type fakeOperatorStore struct {
	trip    ticketing.Trip
	ticket  ticketing.Ticket
	vessels []ticketing.Vessel
}

func (store *fakeOperatorStore) CreateVessel(_ context.Context, vessel ticketing.Vessel) error {
	store.vessels = append(store.vessels, vessel)
	return nil
}
func (store *fakeOperatorStore) ListVessels(_ context.Context, operatorID string) ([]ticketing.Vessel, error) {
	out := make([]ticketing.Vessel, 0)
	for _, vessel := range store.vessels {
		if vessel.OperatorID == operatorID {
			out = append(out, vessel)
		}
	}
	return out, nil
}
func (store *fakeOperatorStore) GetVessel(_ context.Context, operatorID, vesselID string) (ticketing.Vessel, error) {
	for _, vessel := range store.vessels {
		if vessel.VesselID == vesselID && vessel.OperatorID == operatorID {
			return vessel, nil
		}
	}
	return ticketing.Vessel{}, ticketing.ErrNotFound
}
func (store *fakeOperatorStore) UpdateVessel(_ context.Context, vessel ticketing.Vessel) error {
	return nil
}
func (store *fakeOperatorStore) DeleteVessel(_ context.Context, operatorID, vesselID string) error {
	return nil
}
func (store *fakeOperatorStore) CreateTrip(_ context.Context, trip ticketing.Trip) error { return nil }
func (store *fakeOperatorStore) ListTrips(_ context.Context, operatorID string) ([]ticketing.Trip, error) {
	return nil, nil
}
func (store *fakeOperatorStore) GetTripScoped(_ context.Context, operatorID, tripID string) (ticketing.Trip, error) {
	if store.trip.OperatorID != operatorID {
		return ticketing.Trip{}, ticketing.ErrNotFound
	}
	return store.trip, nil
}
func (store *fakeOperatorStore) GetTrip(_ context.Context, tripID string) (ticketing.Trip, error) {
	if store.trip.TripID == "" {
		return ticketing.Trip{}, ticketing.ErrNotFound
	}
	return store.trip, nil
}
func (store *fakeOperatorStore) GetTicket(_ context.Context, ticketID string) (ticketing.Ticket, error) {
	if store.ticket.TicketID == "" {
		return ticketing.Ticket{}, ticketing.ErrNotFound
	}
	return store.ticket, nil
}
func (store *fakeOperatorStore) MarkEmbarked(_ context.Context, operatorID, ticketID string) (ticketing.Ticket, error) {
	ticket := store.ticket
	ticket.Embarked = true
	return ticket, nil
}
func (store *fakeOperatorStore) Dashboard(_ context.Context, operatorID string) (ticketing.Dashboard, error) {
	return ticketing.Dashboard{OperatorID: operatorID, TicketsSold: 12, RevenueNGNMinor: 3000000}, nil
}

type fakeManifestStore struct {
	tickets  []ticketing.Ticket
	recorded []manifest.Manifest
	events   []ticketing.Event
}

func (store *fakeManifestStore) ManifestTickets(_ context.Context, tripID string) ([]ticketing.Ticket, error) {
	return store.tickets, nil
}
func (store *fakeManifestStore) RecordManifest(_ context.Context, record manifest.Manifest, event ticketing.Event) error {
	store.recorded = append(store.recorded, record)
	store.events = append(store.events, event)
	return nil
}
func (store *fakeManifestStore) LatestManifest(_ context.Context, tripID string) (manifest.Manifest, error) {
	return manifest.Manifest{}, ticketing.ErrNotFound
}
func (store *fakeManifestStore) ManifestCompleteness(_ context.Context, operatorID string) (int64, int64, error) {
	return 19, 20, nil
}

func newTestServer(t *testing.T) (*Server, *fakeTicketService, *fakeOperatorStore, *fakeManifestStore) {
	t.Helper()
	tickets := &fakeTicketService{ticket: ticketing.Ticket{
		TicketID: "ticket-1", TripID: "trip-1", OperatorID: "op-1", State: ticketing.StateIssued,
		FareNGNMinor: 250000, Channel: ticketing.ChannelDirect, PassengerDigest: strings.Repeat("a", 64),
		PurchaserPrincipal: "subject-1", CorrelationID: "corr-1", Version: 3,
	}}
	operator := &fakeOperatorStore{
		ticket: tickets.ticket,
		trip: ticketing.Trip{
			TripID: "trip-1", VesselID: "vessel-1", OperatorID: "op-1", RouteReference: "route-1",
			TerminalReference: "terminal-1", ScheduledDeparture: time.Now().Add(2 * time.Hour),
			FareNGNMinor: 250000, Capacity: 50, SeatsReserved: 2, Status: "SCHEDULED",
		},
	}
	manifests := &fakeManifestStore{tickets: []ticketing.Ticket{tickets.ticket}}
	pipeline, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "ferry-httpapi-test"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pipeline.Shutdown(context.Background()) })
	server, err := NewServer(headerAuthenticator{}, tickets, operator, manifests, "0123456789abcdef", 0.95, nil,
		func(context.Context) error { return nil }, pipeline)
	require.NoError(t, err)
	return server, tickets, operator, manifests
}

// TestServerFailsClosedWithoutTelemetry pins the telemetry dependency as
// required, mirroring the other fail-closed constructor checks.
func TestServerFailsClosedWithoutTelemetry(t *testing.T) {
	tickets := &fakeTicketService{}
	operator := &fakeOperatorStore{}
	manifests := &fakeManifestStore{}
	_, err := NewServer(headerAuthenticator{}, tickets, operator, manifests, "0123456789abcdef", 0.95, nil,
		func(context.Context) error { return nil }, nil)
	require.Error(t, err)
}

// withAuth attaches the test identity headers the headerAuthenticator reads.
func withAuth(request *http.Request, principal auth.Principal) *http.Request {
	request.Header.Set("X-Test-Subject", principal.Subject)
	roles := make([]string, 0, len(principal.Roles))
	for role := range principal.Roles {
		roles = append(roles, role)
	}
	request.Header.Set("X-Test-Roles", strings.Join(roles, ","))
	if principal.OperatorID != "" {
		request.Header.Set("X-Test-Operator-Id", principal.OperatorID)
	}
	return request
}

func passengerPrincipal() auth.Principal {
	return auth.Principal{Subject: "subject-1", Roles: map[string]struct{}{RolePassenger: {}}}
}

func TestHealthAndReadiness(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, recorder.Code)

	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestReadinessFailsClosed(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	server.readiness = func(context.Context) error { return errors.New("db down") }
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

func TestPurchaseRequiresIdempotencyKey(t *testing.T) {
	server, tickets, _, _ := newTestServer(t)
	request := withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets",
		strings.NewReader(`{"tripId":"trip-1","passengerRef":"ref-1","channel":"DIRECT"}`)), passengerPrincipal())
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Empty(t, tickets.purchased)
}

func TestPurchaseHappyPath(t *testing.T) {
	server, tickets, _, _ := newTestServer(t)
	request := withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets",
		strings.NewReader(`{"tripId":"trip-1","passengerRef":"ref-1","channel":"DIRECT"}`)), passengerPrincipal())
	request.Header.Set("Idempotency-Key", "key-1")
	request.Header.Set("X-Correlation-Id", "corr-99")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusCreated, recorder.Code)
	require.Len(t, tickets.purchased, 1)
	require.Equal(t, "key-1", tickets.purchased[0].IdempotencyKey)
	require.Equal(t, "corr-99", tickets.purchased[0].CorrelationID)
	require.Equal(t, "subject-1", tickets.purchased[0].Principal)
	require.Contains(t, recorder.Body.String(), `"state":"ISSUED"`)
}

func TestPurchaseForbiddenForOversightRoles(t *testing.T) {
	server, tickets, _, _ := newTestServer(t)
	officer := auth.Principal{Subject: "officer-1", Roles: map[string]struct{}{RoleNIWAOfficer: {}}}
	request := withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets",
		strings.NewReader(`{"tripId":"trip-1","passengerRef":"ref-1","channel":"DIRECT"}`)), officer)
	request.Header.Set("Idempotency-Key", "key-1")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Empty(t, tickets.purchased)
}

func TestUnauthenticatedRequestsFailClosed(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestGetTicketEnforcesOwnership(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	other := auth.Principal{Subject: "subject-2", Roles: map[string]struct{}{RolePassenger: {}}}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil), other))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil), passengerPrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestManifestAccessPolicy(t *testing.T) {
	server, _, _, _ := newTestServer(t)

	// Oversight role: any trip.
	observer := auth.Principal{Subject: "obs-1", Roles: map[string]struct{}{RoleNIMASAObserver: {}}}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/nimasa/trips/trip-1/manifest", nil), observer))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"collection"`)
	require.NotContains(t, recorder.Body.String(), "passengerRef")

	// Owning operator: allowed.
	operator := auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/nimasa/trips/trip-1/manifest", nil), operator))
	require.Equal(t, http.StatusOK, recorder.Code)

	// Other operator: denied at the service layer.
	stranger := auth.Principal{Subject: "op-stranger", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-2"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/nimasa/trips/trip-1/manifest", nil), stranger))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	// Passenger: denied.
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/nimasa/trips/trip-1/manifest", nil), passengerPrincipal()))
	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestOperatorScopeEnforced(t *testing.T) {
	server, _, _, _ := newTestServer(t)
	// Operator role without an operator_id claim: fail closed.
	noScope := auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/operator/dashboard", nil), noScope))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	operator := auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/operator/dashboard", nil), operator))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"ticketsSold":12`)
	require.Contains(t, recorder.Body.String(), `"manifestCompleteness"`)
}

func TestManifestExportTriggerWritesOutboxEvent(t *testing.T) {
	server, _, _, manifests := newTestServer(t)
	operator := auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}
	request := withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/trips/trip-1/manifest/export", nil), operator)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusCreated, recorder.Code)
	require.Len(t, manifests.recorded, 1)
	require.Len(t, manifests.events, 1)
	require.Equal(t, ticketing.EventManifestExported, manifests.events[0].EventType)
	require.Equal(t, ticketing.TopicManifest, manifests.events[0].Topic)
	require.Equal(t, manifests.recorded[0].PassengerCount, 1)
	require.NotEmpty(t, manifests.recorded[0].DigestSHA256)

	// A different operator cannot export another operator's manifest.
	stranger := auth.Principal{Subject: "op-stranger", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-2"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/trips/trip-1/manifest/export", nil), stranger))
	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Len(t, manifests.recorded, 1)
}

func TestVesselCRUDOperatorScoped(t *testing.T) {
	server, _, operator, _ := newTestServer(t)
	principal := auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}

	create := withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/vessels",
		strings.NewReader(`{"name":"MV Lagoon Star","imoNumber":"NG-1234","capacity":60,"active":true}`)), principal)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, create)
	require.Equal(t, http.StatusCreated, recorder.Code)
	require.Len(t, operator.vessels, 1)
	require.Equal(t, "op-1", operator.vessels[0].OperatorID)

	list := withAuth(httptest.NewRequest(http.MethodGet, "/v1/operator/vessels", nil), principal)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, list)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), "MV Lagoon Star")

	// Passengers cannot reach the operator portal.
	denied := withAuth(httptest.NewRequest(http.MethodGet, "/v1/operator/vessels", nil), passengerPrincipal())
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, denied)
	require.Equal(t, http.StatusForbidden, recorder.Code)
}
