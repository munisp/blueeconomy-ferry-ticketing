// Package auth authenticates requests against Keycloak-issued RS256 JWTs
// (JWKS-validated, issuer/audience checked, short key TTL) or, behind the
// platform edge, via the trusted-proxy identity headers. It mirrors the
// administration-service pattern and fails closed on every ambiguity.
package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Principal is the authenticated caller: the Keycloak subject, its realm and
// client roles, and the operator scope (empty for non-operator principals).
type Principal struct {
	Subject    string
	Roles      map[string]struct{}
	OperatorID string
}

// HasRole reports whether the principal carries role.
func (principal Principal) HasRole(role string) bool {
	_, ok := principal.Roles[role]
	return ok
}

type contextKey struct{}

// WithPrincipal attaches the authenticated principal to the context.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, principal)
}

// PrincipalFrom returns the authenticated principal; ok is false when the
// request was not authenticated (a middleware defect — handlers must fail
// closed).
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok && principal.Subject != ""
}

// Authenticator resolves a request to a Principal.
type Authenticator interface {
	Authenticate(*http.Request) (Principal, error)
}

// TrustedProxyAuthenticator trusts identity headers only from approved proxy
// CIDRs presenting the approved proxy identity header.
type TrustedProxyAuthenticator struct {
	CIDRs    []*net.IPNet
	Identity string
}

// Authenticate implements Authenticator.
func (auth TrustedProxyAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	remoteHost, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		remoteHost = strings.TrimSpace(request.RemoteAddr)
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return Principal{}, errors.New("trusted proxy source address is invalid")
	}
	allowed := false
	for _, network := range auth.CIDRs {
		if network.Contains(remoteIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Principal{}, errors.New("request source is not an approved trusted proxy")
	}
	if strings.TrimSpace(request.Header.Get("X-Blueeconomy-Authenticated-By")) != auth.Identity {
		return Principal{}, errors.New("trusted proxy identity is missing or invalid")
	}
	subject, err := validatedSubject(request.Header.Get("X-Blueeconomy-Authenticated-Subject"))
	if err != nil {
		return Principal{}, err
	}
	roles, err := validatedRoles(request.Header.Get("X-Blueeconomy-Authenticated-Roles"))
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		Subject:    subject,
		Roles:      roles,
		OperatorID: strings.TrimSpace(request.Header.Get("X-Blueeconomy-Operator-Id")),
	}, nil
}

// OIDCAuthenticator validates Keycloak RS256 JWTs against the realm JWKS.
// Only RSA signature keys of at least 2048 bits are trusted; the key set is
// refreshed with a short TTL and redirects are not followed.
type OIDCAuthenticator struct {
	Issuer   string
	Audience string
	JWKSURL  *url.URL

	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	loadedAt time.Time
}

// NewOIDCAuthenticator builds the authenticator, wiring a pinned CA when
// caFile is set.
func NewOIDCAuthenticator(issuer, audience string, jwksURL *url.URL, caFile string) (*OIDCAuthenticator, error) {
	if issuer == "" || audience == "" || jwksURL == nil {
		return nil, errors.New("OIDC issuer, audience and JWKS URL are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA file: %w", err)
		}
		pool, poolErr := x509.SystemCertPool()
		if poolErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("OIDC CA file did not contain a usable PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &OIDCAuthenticator{
		Issuer:   issuer,
		Audience: audience,
		JWKSURL:  jwksURL,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("JWKS redirects are not permitted")
			},
		},
		keys: make(map[string]*rsa.PublicKey),
	}, nil
}

// Authenticate implements Authenticator.
func (auth *OIDCAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return Principal{}, errors.New("Bearer authorization is required")
	}
	token := strings.TrimSpace(parts[1])
	segments := strings.Split(token, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return Principal{}, errors.New("JWT compact serialization is invalid")
	}
	headerBytes, err := decodeBase64URL(segments[0])
	if err != nil {
		return Principal{}, errors.New("JWT header is invalid")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "RS256" || strings.TrimSpace(header.Kid) == "" {
		return Principal{}, errors.New("JWT algorithm or key ID is invalid")
	}
	key, err := auth.key(header.Kid, true)
	if err != nil {
		return Principal{}, err
	}
	signature, err := decodeBase64URL(segments[2])
	if err != nil {
		return Principal{}, errors.New("JWT signature is invalid")
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return Principal{}, errors.New("JWT signature verification failed")
	}
	payloadBytes, err := decodeBase64URL(segments[1])
	if err != nil {
		return Principal{}, errors.New("JWT claims are invalid")
	}
	var claims struct {
		Issuer    string          `json:"iss"`
		Subject   string          `json:"sub"`
		Audience  json.RawMessage `json:"aud"`
		Expires   json.Number     `json:"exp"`
		NotBefore json.Number     `json:"nbf"`
		Realm     struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
		OperatorID string `json:"operator_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return Principal{}, errors.New("JWT claims are invalid")
	}
	if claims.Issuer != auth.Issuer || !audienceContains(claims.Audience, auth.Audience) {
		return Principal{}, errors.New("JWT issuer or audience is invalid")
	}
	now := time.Now().Unix()
	expires, err := claims.Expires.Int64()
	if err != nil || now >= expires {
		return Principal{}, errors.New("JWT is expired or has no valid expiry")
	}
	if claims.NotBefore != "" {
		notBefore, parseErr := claims.NotBefore.Int64()
		if parseErr != nil || now < notBefore {
			return Principal{}, errors.New("JWT is not yet valid")
		}
	}
	subject, err := validatedSubject(claims.Subject)
	if err != nil {
		return Principal{}, err
	}
	roles := make(map[string]struct{})
	for _, role := range claims.Realm.Roles {
		if trimmed := strings.TrimSpace(role); trimmed != "" {
			roles[trimmed] = struct{}{}
		}
	}
	for _, access := range claims.ResourceAccess {
		for _, role := range access.Roles {
			if trimmed := strings.TrimSpace(role); trimmed != "" {
				roles[trimmed] = struct{}{}
			}
		}
	}
	return Principal{Subject: subject, Roles: roles, OperatorID: strings.TrimSpace(claims.OperatorID)}, nil
}

func (auth *OIDCAuthenticator) key(kid string, refresh bool) (*rsa.PublicKey, error) {
	auth.mu.RLock()
	key := auth.keys[kid]
	fresh := time.Since(auth.loadedAt) < 5*time.Minute
	auth.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if !refresh {
		return nil, errors.New("JWT key is not trusted")
	}
	if err := auth.loadKeys(); err != nil {
		return nil, fmt.Errorf("load OIDC JWKS: %w", err)
	}
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	if key := auth.keys[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("JWT key ID is not trusted")
}

func (auth *OIDCAuthenticator) loadKeys() error {
	request, err := http.NewRequest(http.MethodGet, auth.JWKSURL.String(), nil)
	if err != nil {
		return err
	}
	response, err := auth.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}
	loaded := make(map[string]*rsa.PublicKey)
	for _, item := range document.Keys {
		if item.Kty != "RSA" || item.Use != "sig" || item.Alg != "RS256" || item.Kid == "" || item.N == "" || item.E == "" {
			continue
		}
		modulus, err := decodeBase64URL(item.N)
		if err != nil {
			continue
		}
		exponentBytes, err := decodeBase64URL(item.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 {
			continue
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
		if key.N.BitLen() < 2048 {
			continue
		}
		loaded[item.Kid] = key
	}
	if len(loaded) == 0 {
		return errors.New("JWKS contains no approved RSA signing keys")
	}
	auth.mu.Lock()
	auth.keys = loaded
	auth.loadedAt = time.Now()
	auth.mu.Unlock()
	return nil
}

// Middleware authenticates every request and attaches the Principal.
func Middleware(authenticator Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, err := authenticator.Authenticate(request)
		if err != nil {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		next.ServeHTTP(writer, request.WithContext(WithPrincipal(request.Context(), principal)))
	})
}

// RequireRoles admits principals carrying at least one of the roles.
func RequireRoles(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := PrincipalFrom(request.Context())
		if !ok {
			writeForbidden(writer)
			return
		}
		for _, role := range roles {
			if principal.HasRole(role) {
				next.ServeHTTP(writer, request)
				return
			}
		}
		writeForbidden(writer)
	})
}

func writeForbidden(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusForbidden)
	_, _ = writer.Write([]byte(`{"error":"forbidden"}`))
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil {
		return false
	}
	for _, value := range multiple {
		if value == expected {
			return true
		}
	}
	return false
}

func validatedSubject(value string) (string, error) {
	subject := strings.TrimSpace(value)
	if subject == "" || len(subject) > 512 {
		return "", errors.New("authenticated subject is required")
	}
	return subject, nil
}

func validatedRoles(value string) (map[string]struct{}, error) {
	roles := make(map[string]struct{})
	for _, role := range strings.Split(value, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if len(role) > 128 || strings.ContainsAny(role, "\x00\r\n") {
			return nil, errors.New("authenticated roles header is invalid")
		}
		roles[role] = struct{}{}
	}
	return roles, nil
}
