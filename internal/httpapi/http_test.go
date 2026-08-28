package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/manifest"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
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
func (store *fakeOperatorStore) Dashboard(_ context.Context, operatorID string) (ticketing.Dashboard, error) {
	return ticketing.Dashboard{OperatorID: operatorID, TicketsSold: 12, RevenueNGNMinor: 3000000}, nil
}

// fakeBoardingStore is an in-memory ticketing.BoardingStore honoring the
// first-scan-wins atomic consume contract (single mutex-guarded map).
type fakeBoardingStore struct {
	mu      sync.Mutex
	tickets map[string]ticketing.Ticket
	trips   map[string]ticketing.Trip
	events  []ticketing.Event
}

func newFakeBoardingStore() *fakeBoardingStore {
	return &fakeBoardingStore{
		tickets: make(map[string]ticketing.Ticket),
		trips:   make(map[string]ticketing.Trip),
	}
}

func (store *fakeBoardingStore) GetTicket(_ context.Context, ticketID string) (ticketing.Ticket, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[ticketID]
	if !ok {
		return ticketing.Ticket{}, ticketing.ErrNotFound
	}
	return ticket, nil
}

func (store *fakeBoardingStore) GetTrip(_ context.Context, tripID string) (ticketing.Trip, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	trip, ok := store.trips[tripID]
	if !ok {
		return ticketing.Trip{}, ticketing.ErrNotFound
	}
	return trip, nil
}

func (store *fakeBoardingStore) ConsumeBoarding(_ context.Context, operatorID, ticketID, boardedBy, artifactKid string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	ticket, ok := store.tickets[ticketID]
	if !ok || ticket.OperatorID != operatorID || ticket.State != ticketing.StateIssued || ticket.BoardedAt != nil {
		return false, nil
	}
	now := time.Now().UTC()
	ticket.Embarked = true
	ticket.BoardedAt = &now
	ticket.BoardedBy = boardedBy
	ticket.ArtifactKid = artifactKid
	store.tickets[ticketID] = ticket
	return true, nil
}

func (store *fakeBoardingStore) AppendEvent(_ context.Context, event ticketing.Event) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.events = append(store.events, event)
	return nil
}

func (store *fakeBoardingStore) fraudEvents() []ticketing.Event {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]ticketing.Event(nil), store.events...)
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

func newTestServer(t *testing.T) (*Server, *fakeTicketService, *fakeOperatorStore, *fakeManifestStore, *fakeBoardingStore) {
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
	boardingStore := newFakeBoardingStore()
	boardingStore.tickets[tickets.ticket.TicketID] = tickets.ticket
	boardingStore.trips[operator.trip.TripID] = operator.trip
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySet, err := ticketproof.NewKeySet(key, 1, nil)
	require.NoError(t, err)
	boarding, err := ticketing.NewBoardingService(boardingStore, keySet, "test-window-secret-0123456789")
	require.NoError(t, err)
	pipeline, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "ferry-httpapi-test"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pipeline.Shutdown(context.Background()) })
	server, err := NewServer(headerAuthenticator{}, tickets, operator, manifests, boarding, "0123456789abcdef", 0.95, nil,
		func(context.Context) error { return nil }, pipeline)
	require.NoError(t, err)
	return server, tickets, operator, manifests, boardingStore
}

// TestServerFailsClosedWithoutTelemetry pins the telemetry dependency as
// required, mirroring the other fail-closed constructor checks.
func TestServerFailsClosedWithoutTelemetry(t *testing.T) {
	tickets := &fakeTicketService{}
	operator := &fakeOperatorStore{}
	manifests := &fakeManifestStore{}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySet, err := ticketproof.NewKeySet(key, 1, nil)
	require.NoError(t, err)
	boarding, err := ticketing.NewBoardingService(newFakeBoardingStore(), keySet, "test-window-secret-0123456789")
	require.NoError(t, err)
	_, err = NewServer(headerAuthenticator{}, tickets, operator, manifests, boarding, "0123456789abcdef", 0.95, nil,
		func(context.Context) error { return nil }, nil)
	require.Error(t, err)
}

func TestServerFailsClosedWithoutBoarding(t *testing.T) {
	pipeline, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "ferry-httpapi-test"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pipeline.Shutdown(context.Background()) })
	_, err = NewServer(headerAuthenticator{}, &fakeTicketService{}, &fakeOperatorStore{}, &fakeManifestStore{}, nil,
		"0123456789abcdef", 0.95, nil, func(context.Context) error { return nil }, pipeline)
	require.Error(t, err, "no boarding service: fail closed")
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
	server, _, _, _, _ := newTestServer(t)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, recorder.Code)

	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestReadinessFailsClosed(t *testing.T) {
	server, _, _, _, _ := newTestServer(t)
	server.readiness = func(context.Context) error { return errors.New("db down") }
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
}

func TestPurchaseRequiresIdempotencyKey(t *testing.T) {
	server, tickets, _, _, _ := newTestServer(t)
	request := withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets",
		strings.NewReader(`{"tripId":"trip-1","passengerRef":"ref-1","channel":"DIRECT"}`)), passengerPrincipal())
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Empty(t, tickets.purchased)
}

func TestPurchaseHappyPath(t *testing.T) {
	server, tickets, _, _, _ := newTestServer(t)
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
	server, tickets, _, _, _ := newTestServer(t)
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
	server, _, _, _, _ := newTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestGetTicketEnforcesOwnership(t *testing.T) {
	server, _, _, _, _ := newTestServer(t)
	other := auth.Principal{Subject: "subject-2", Roles: map[string]struct{}{RolePassenger: {}}}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil), other))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1", nil), passengerPrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
}

func TestManifestAccessPolicy(t *testing.T) {
	server, _, _, _, _ := newTestServer(t)

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
	server, _, _, _, _ := newTestServer(t)
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
	server, _, _, manifests, _ := newTestServer(t)
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
	server, _, operator, _, _ := newTestServer(t)
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

// --- Signed ticket artifacts: mint, stateless verify, first-scan-wins ---

func operatorPrincipal() auth.Principal {
	return auth.Principal{Subject: "op-subject", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}
}

func mintArtifact(t *testing.T, server *Server) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1/artifact", nil), passengerPrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var body struct {
		Artifact string `json:"artifact"`
		KeyID    string `json:"kid"`
	}
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&body))
	require.NotEmpty(t, body.Artifact)
	require.NotEmpty(t, body.KeyID)
	return body.Artifact
}

func TestArtifactAccessPolicy(t *testing.T) {
	server, _, _, _, _ := newTestServer(t)

	// Owner (purchaser) mints.
	mintArtifact(t, server)

	// Owning operator mints.
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1/artifact", nil), operatorPrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)

	// Another passenger and a foreign operator are denied (bearer capability).
	stranger := auth.Principal{Subject: "subject-2", Roles: map[string]struct{}{RolePassenger: {}}}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1/artifact", nil), stranger))
	require.Equal(t, http.StatusForbidden, recorder.Code)
	foreign := auth.Principal{Subject: "op-stranger", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-2"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1/artifact", nil), foreign))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	// Oversight roles cannot mint artifacts even though they may read tickets.
	officer := auth.Principal{Subject: "officer-1", Roles: map[string]struct{}{RoleNIWAOfficer: {}}}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-1/artifact", nil), officer))
	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestVerifyEndpointStateless(t *testing.T) {
	server, _, _, _, boardingStore := newTestServer(t)
	token := mintArtifact(t, server)

	// Gate role: valid artifact verifies.
	gate := auth.Principal{Subject: "gate-1", Roles: map[string]struct{}{RoleGate: {}}}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets/verify",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), gate))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"valid":true`)
	require.Contains(t, recorder.Body.String(), `"ticketId":"ticket-1"`)
	require.Empty(t, boardingStore.fraudEvents())

	// Operator role is also admitted; passengers are not.
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets/verify",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), passengerPrincipal()))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	// Tampered artifact: 401 plus a CONFIDENTIAL fraud-telemetry event.
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/tickets/verify",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token[:len(token)-2]+"zz"))), gate))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	events := boardingStore.fraudEvents()
	require.Len(t, events, 1)
	require.Equal(t, ticketing.EventTicketVerificationFailed, events[0].EventType)
	require.Equal(t, ticketing.TopicTicketing, events[0].Topic)
}

func TestEmbarkWithArtifactFirstScanWins(t *testing.T) {
	server, _, _, _, boardingStore := newTestServer(t)
	token := mintArtifact(t, server)
	operator := operatorPrincipal()

	embark := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-1/embark",
			strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), operator))
		return recorder
	}

	first := embark()
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), `"embarked":true`)
	require.Contains(t, first.Body.String(), `"artifactKid"`)

	// Second presentation of the same artifact: 409 BOARDING_ALREADY_CONSUMED
	// plus the duplicate-presentation fraud event.
	second := embark()
	require.Equal(t, http.StatusConflict, second.Code)
	require.Contains(t, second.Body.String(), "BOARDING_ALREADY_CONSUMED")
	events := boardingStore.fraudEvents()
	require.Len(t, events, 1)
	require.Equal(t, ticketing.EventTicketDuplicatePresentation, events[0].EventType)
	require.Equal(t, "ticket-1", events[0].Payload["ticket_id"])
	require.Equal(t, "op-subject", events[0].Payload["principal_id"])
}

func TestEmbarkFirstScanWinsRace(t *testing.T) {
	server, _, _, _, _ := newTestServer(t)
	token := mintArtifact(t, server)
	operator := operatorPrincipal()

	// Two gangways present the same artifact concurrently: exactly one wins.
	const gangways = 2
	codes := make(chan int, gangways)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < gangways; index++ {
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					codes <- -1
				}
			}()
			start.Wait()
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-1/embark",
				strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), operator))
			codes <- recorder.Code
		}()
	}
	start.Done()
	results := make(map[int]int)
	for index := 0; index < gangways; index++ {
		results[<-codes]++
	}
	require.Equal(t, 1, results[http.StatusOK], "exactly one boarding wins, got %v", results)
	require.Equal(t, 1, results[http.StatusConflict], "the loser sees 409, got %v", results)
}

func TestEmbarkLegacyPathFlaggedAndGuarded(t *testing.T) {
	server, _, _, _, boardingStore := newTestServer(t)
	operator := operatorPrincipal()

	// Legacy raw-ticket-id embark (no body) still works...
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-1/embark", nil), operator))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"embarked":true`)

	// ...and the first-scan-wins guard covers the legacy path too: a signed
	// artifact presented afterwards is a duplicate.
	token := mintArtifact(t, server)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-1/embark",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), operator))
	require.Equal(t, http.StatusConflict, recorder.Code)
	require.NotEmpty(t, boardingStore.fraudEvents())
}

func TestEmbarkRejectsForgedAndMismatchedArtifacts(t *testing.T) {
	server, _, _, _, boardingStore := newTestServer(t)
	operator := operatorPrincipal()

	// Artifact signed by an untrusted key.
	_, rogueKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rogueSet, err := ticketproof.NewKeySet(rogueKey, 1, nil)
	require.NoError(t, err)
	digest := strings.Repeat("a", 64)
	rogueToken, err := rogueSet.Sign(ticketproof.Payload{
		TicketID: "ticket-1", TripID: "trip-1", Seat: 7, IssuedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(), HolderDigest: digest,
	}, "test-window-secret-0123456789", time.Now().UTC())
	require.NoError(t, err)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-1/embark",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, rogueToken))), operator))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Valid artifact for another ticket id presented against ticket-1.
	token := mintArtifact(t, server)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(httptest.NewRequest(http.MethodPost, "/v1/operator/tickets/ticket-999/embark",
		strings.NewReader(fmt.Sprintf(`{"artifact":%q}`, token))), operator))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)

	events := boardingStore.fraudEvents()
	require.Len(t, events, 2, "both forgeries emit TicketVerificationFailed")
	for _, event := range events {
		require.Equal(t, ticketing.EventTicketVerificationFailed, event.EventType)
	}
	require.Equal(t, "unknown_kid", events[0].Payload["reason"])
	require.Equal(t, "ticket_id_mismatch", events[1].Payload["reason"])
}
