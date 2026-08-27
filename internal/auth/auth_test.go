package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type jwksFixture struct {
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
	issuer string
}

func newJWKSFixture(t *testing.T) *jwksFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	fixture := &jwksFixture{key: key, kid: "key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(writer http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(writer, `{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}`, fixture.kid, n, e)
	})
	fixture.server = httptest.NewServer(mux)
	fixture.issuer = "https://keycloak.example/realms/blueeconomy"
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *jwksFixture) token(t *testing.T, mutate func(claims map[string]any)) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":"%s"}`, fixture.kid)))
	claims := map[string]any{
		"iss":          fixture.issuer,
		"sub":          "subject-1",
		"aud":          "ferry-ticketing",
		"exp":          time.Now().Add(5 * time.Minute).Unix(),
		"realm_access": map[string]any{"roles": []string{"operator"}},
		"operator_id":  "op-1",
	}
	if mutate != nil {
		mutate(claims)
	}
	claimsBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(header + "." + payload))
	signed, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signed)
}

func (fixture *jwksFixture) authenticator(t *testing.T) *OIDCAuthenticator {
	t.Helper()
	jwksURL, err := url.Parse(fixture.server.URL + "/jwks")
	require.NoError(t, err)
	authenticator, err := NewOIDCAuthenticator(fixture.issuer, "ferry-ticketing", jwksURL, "")
	require.NoError(t, err)
	return authenticator
}

func requestWithToken(token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/v1/tickets", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func TestOIDCAuthenticatorAcceptsValidToken(t *testing.T) {
	fixture := newJWKSFixture(t)
	authenticator := fixture.authenticator(t)
	principal, err := authenticator.Authenticate(requestWithToken(fixture.token(t, nil)))
	require.NoError(t, err)
	require.Equal(t, "subject-1", principal.Subject)
	require.True(t, principal.HasRole("operator"))
	require.Equal(t, "op-1", principal.OperatorID)
}

func TestOIDCAuthenticatorRejects(t *testing.T) {
	fixture := newJWKSFixture(t)
	authenticator := fixture.authenticator(t)

	_, err := authenticator.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	require.Error(t, err, "missing bearer token")

	_, err = authenticator.Authenticate(requestWithToken(fixture.token(t, func(claims map[string]any) {
		claims["iss"] = "https://attacker.example"
	})))
	require.Error(t, err, "wrong issuer")

	_, err = authenticator.Authenticate(requestWithToken(fixture.token(t, func(claims map[string]any) {
		claims["aud"] = "other-service"
	})))
	require.Error(t, err, "wrong audience")

	_, err = authenticator.Authenticate(requestWithToken(fixture.token(t, func(claims map[string]any) {
		claims["exp"] = time.Now().Add(-time.Minute).Unix()
	})))
	require.Error(t, err, "expired token")

	// Tampered payload: signature no longer matches.
	token := fixture.token(t, nil)
	segments := splitToken(token)
	tampered := segments[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+fixture.issuer+`","sub":"subject-1","aud":"ferry-ticketing","exp":99999999999}`)) + "." + segments[2]
	_, err = authenticator.Authenticate(requestWithToken(tampered))
	require.Error(t, err, "tampered payload")
}

func splitToken(token string) []string {
	var segments []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			segments = append(segments, token[start:i])
			start = i + 1
		}
	}
	return append(segments, token[start:])
}

func TestJWKSRejectsUndersizedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(small.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(small.PublicKey.E)).Bytes())
		fmt.Fprintf(writer, `{"keys":[{"kty":"RSA","kid":"weak","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}`, n, e)
	}))
	defer server.Close()
	jwksURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	authenticator, err := NewOIDCAuthenticator("https://issuer", "aud", jwksURL, "")
	require.NoError(t, err)
	require.Error(t, authenticator.loadKeys(), "no approved >=2048-bit keys: fail closed")
}

func TestTrustedProxyAuthenticator(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	authenticator := TrustedProxyAuthenticator{CIDRs: []*net.IPNet{network}, Identity: "edge-1"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:5000"
	request.Header.Set("X-Blueeconomy-Authenticated-By", "edge-1")
	request.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-9")
	request.Header.Set("X-Blueeconomy-Authenticated-Roles", "passenger, operator")
	request.Header.Set("X-Blueeconomy-Operator-Id", "op-9")
	principal, err := authenticator.Authenticate(request)
	require.NoError(t, err)
	require.Equal(t, "subject-9", principal.Subject)
	require.True(t, principal.HasRole("passenger"))
	require.True(t, principal.HasRole("operator"))
	require.Equal(t, "op-9", principal.OperatorID)

	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "192.168.1.1:5000"
	untrusted.Header.Set("X-Blueeconomy-Authenticated-By", "edge-1")
	untrusted.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-9")
	_, err = authenticator.Authenticate(untrusted)
	require.Error(t, err, "untrusted source fails closed")

	wrongIdentity := httptest.NewRequest(http.MethodGet, "/", nil)
	wrongIdentity.RemoteAddr = "10.1.2.3:5000"
	wrongIdentity.Header.Set("X-Blueeconomy-Authenticated-Subject", "subject-9")
	_, err = authenticator.Authenticate(wrongIdentity)
	require.Error(t, err)
}

func TestRequireRolesMiddleware(t *testing.T) {
	handler := RequireRoles(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}), "niwa-officer", "nimasa-observer")

	admitted := httptest.NewRequest(http.MethodGet, "/", nil)
	admitted = admitted.WithContext(WithPrincipal(admitted.Context(), Principal{Subject: "s", Roles: map[string]struct{}{"nimasa-observer": {}}}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, admitted)
	require.Equal(t, http.StatusNoContent, recorder.Code)

	denied := httptest.NewRequest(http.MethodGet, "/", nil)
	denied = denied.WithContext(WithPrincipal(denied.Context(), Principal{Subject: "s", Roles: map[string]struct{}{"passenger": {}}}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, denied)
	require.Equal(t, http.StatusForbidden, recorder.Code)

	anonymous := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, anonymous)
	require.Equal(t, http.StatusForbidden, recorder.Code, "no principal: fail closed")
}
