package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/auth"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/telemetry"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketproof"
)

// newVerificationKeysServer builds a server whose boarding service signs with
// `current` at epoch 2 and trusts `previous` (epoch 1) until graceUntil.
func newVerificationKeysServer(t *testing.T, graceUntil time.Time) (
	server *Server, current ed25519.PrivateKey, previous ed25519.PrivateKey,
) {
	t.Helper()
	var err error
	_, current, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, previous, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keySet, err := ticketproof.NewKeySet(current, 2, &ticketproof.RotatedKey{
		Public:     previous.Public().(ed25519.PublicKey),
		Epoch:      1,
		GraceUntil: graceUntil,
	})
	require.NoError(t, err)
	boarding, err := ticketing.NewBoardingService(newFakeBoardingStore(), keySet, "test-window-secret-0123456789")
	require.NoError(t, err)
	pipeline, err := telemetry.Setup(context.Background(), telemetry.Config{ServiceName: "ferry-httpapi-keys-test"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pipeline.Shutdown(context.Background()) })
	server, err = NewServer(headerAuthenticator{}, &fakeTicketService{}, &fakeOperatorStore{}, &fakeManifestStore{}, boarding,
		"0123456789abcdef", 0.95, nil, func(context.Context) error { return nil }, pipeline)
	require.NoError(t, err)
	return server, current, previous
}

func kidOf(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	digest := sha256.Sum256(key.Public().(ed25519.PublicKey))
	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

func gatePrincipal() auth.Principal {
	return auth.Principal{Subject: "gate-1", Roles: map[string]struct{}{RoleGate: {}}}
}

// TestVerificationKeysShape pins the exact wire shape the mobile inspector
// parser (blueeconomy-mobile src/core/api/fetchers.ts) consumes: current +
// previous with kid, public_key_hex, epoch (number) and grace_until_unix.
func TestVerificationKeysShape(t *testing.T) {
	grace := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	server, current, previous := newVerificationKeysServer(t, grace)

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), gatePrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)

	// Decode generically to pin JSON types (epoch/grace are numbers, not strings).
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	require.Len(t, body, 2, "exactly current + previous")

	currentView := body["current"]
	require.Equal(t, kidOf(t, current), currentView["kid"])
	require.Equal(t, "Ed25519", currentView["algorithm"])
	require.Equal(t, hex.EncodeToString(current.Public().(ed25519.PublicKey)), currentView["public_key_hex"])
	require.InDelta(t, 2, currentView["epoch"], 0)
	require.Equal(t, float64(2), currentView["epoch"], "epoch must be a JSON number")
	require.Nil(t, currentView["grace_until_unix"], "current key carries no grace deadline")

	previousView := body["previous"]
	require.NotNil(t, previousView)
	require.Equal(t, kidOf(t, previous), previousView["kid"])
	require.Equal(t, "Ed25519", previousView["algorithm"])
	require.Equal(t, hex.EncodeToString(previous.Public().(ed25519.PublicKey)), previousView["public_key_hex"])
	require.Equal(t, float64(1), previousView["epoch"])
	require.Equal(t, float64(grace.Unix()), previousView["grace_until_unix"])
}

// TestVerificationKeysNoPrivateMaterial proves the endpoint serves only
// public material: no private key bytes, no window secret.
func TestVerificationKeysNoPrivateMaterial(t *testing.T) {
	server, current, previous := newVerificationKeysServer(t, time.Now().Add(time.Hour))

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), gatePrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
	payload := recorder.Body.String()

	privateHex := hex.EncodeToString(current)
	seedHex := hex.EncodeToString(current.Seed())
	previousPrivateHex := hex.EncodeToString(previous)
	require.NotContains(t, payload, privateHex)
	require.NotContains(t, payload, seedHex)
	require.NotContains(t, payload, previousPrivateHex)
	require.NotContains(t, payload, "test-window-secret-0123456789")
	require.NotContains(t, payload, "private")

	// The public keys ARE present (hex of the raw 32-byte public halves).
	require.Contains(t, payload, hex.EncodeToString(current.Public().(ed25519.PublicKey)))
	require.Contains(t, payload, hex.EncodeToString(previous.Public().(ed25519.PublicKey)))
}

// TestVerificationKeysRotationBoundary: inside the grace window the previous
// key is distributed; at/past the deadline it is no longer trusted and the
// endpoint reports current only (fail-closed, matching server verification).
func TestVerificationKeysRotationBoundary(t *testing.T) {
	// Grace still open: previous present.
	server, _, _ := newVerificationKeysServer(t, time.Now().Add(time.Minute))
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), gatePrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
	var withGrace map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &withGrace))
	require.NotNil(t, withGrace["previous"], "previous key is served inside the grace window")

	// Grace expired: previous withheld.
	server, _, _ = newVerificationKeysServer(t, time.Now().Add(-time.Minute))
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), gatePrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
	var expired map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &expired))
	require.Nil(t, expired["previous"], "previous key is withheld once the grace window closes")
	require.NotNil(t, expired["current"])
}

// TestVerificationKeysNoRotationConfigured: a single-key deployment serves
// current with an explicit null previous.
func TestVerificationKeysNoRotationConfigured(t *testing.T) {
	server, _, _, _, _ := newTestServer(t) // epoch 1, no previous key
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), gatePrincipal()))
	require.Equal(t, http.StatusOK, recorder.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	require.Contains(t, body, "previous")
	require.Nil(t, body["previous"])
	require.NotNil(t, body["current"])
}

// TestVerificationKeysAuthz: authenticated verifier roles (operator, gate)
// only, mirroring POST /v1/tickets/verify.
func TestVerificationKeysAuthz(t *testing.T) {
	server, _, _ := newVerificationKeysServer(t, time.Now().Add(time.Hour))

	// Unauthenticated: 401.
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil))
	require.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Passenger: not a verifier role, 403.
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), passengerPrincipal()))
	require.Equal(t, http.StatusForbidden, recorder.Code)

	// Operator: allowed.
	operator := auth.Principal{Subject: "op-1", Roles: map[string]struct{}{RoleOperator: {}}, OperatorID: "op-1"}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, withAuth(
		httptest.NewRequest(http.MethodGet, "/v1/tickets/verification-keys", nil), operator))
	require.Equal(t, http.StatusOK, recorder.Code)
}
