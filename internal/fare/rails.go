package fare

// rails.go — PRA-134: LIVE bank-rail adapters for BlueFare top-ups.
//
// Two real clients behind env-gated config:
//
//	MojaloopRail  FSPIOP quoting -> transfer flow (FSPIOP-Source/Destination
//	              headers, versioned JSON content types, trace-context
//	              propagation per the fincontrols span-links discipline)
//	NIPRail       NIP-style reference credit initiation (signed bearer
//	              request carrying the unique top-up reference as narration)
//
// Doctrine: FAIL-CLOSED when unconfigured or partially configured; NO
// simulated rails on production paths. Rail initiation never credits the
// account: credit still happens only on the verified rail webhook — an
// accepted initiation is a promise, not money.
//
// TLS material comes from file paths (ExternalSecrets mount contract):
// FERRY_MOJALOOP_TLS_CERT_FILE / _KEY_FILE / _CA_FILE (likewise FERRY_NIP_*).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// ErrRailNotConfigured rejects a top-up on a rail channel whose adapter has
// no live configuration (fail closed — never a synthetic rail).
var ErrRailNotConfigured = errors.New("bank rail is not configured for this channel")

// RailInstruction is one outbound rail initiation.
type RailInstruction struct {
	Reference      string // the durable top-up reference (rail echo key)
	AmountNGNMinor int64
	PayeeRef       string // BlueFare receiving alias at the rail
	Narration      string
}

// RailInitiation is the rail's acceptance (NOT a credit).
type RailInitiation struct {
	ExternalRef string
}

// RailClient is one live bank-rail adapter.
type RailClient interface {
	Initiate(ctx context.Context, instruction RailInstruction) (RailInitiation, error)
}

// railHTTPClient builds the (optionally mutual-TLS) HTTP transport from
// ExternalSecrets-mounted files. Any configured-but-unreadable material
// fails closed at boot.
func railHTTPClient(certFile, keyFile, caFile string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if certFile == "" && keyFile == "" && caFile == "" {
		return &http.Client{Timeout: 15 * time.Second, Transport: transport}, nil
	}
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, errors.New("TLS cert, key and CA files must all be set (fail-closed)")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load rail TLS keypair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read rail CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("rail CA file carries no certificates")
	}
	transport.TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}, nil
}

// injectTraceContext propagates the current span into the rail request
// (the fincontrols FSPIOP span-links discipline: rail legs join the same
// trace, never a parallel telemetry path). The deployment propagator runs
// first; W3C traceparent is guaranteed for rail interop even when the
// deployment configures a different default.
func injectTraceContext(ctx context.Context, request *http.Request) {
	carrier := propagation.HeaderCarrier(request.Header)
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	propagation.TraceContext{}.Inject(ctx, carrier)
}

// ---------------------------------------------------------------------------
// Mojaloop FSPIOP adapter.
// ---------------------------------------------------------------------------

// MojaloopRail speaks FSPIOP 1.0 quoting + transfer to a scheme adapter.
type MojaloopRail struct {
	baseURL     string
	source      string
	destination string
	payeeRef    string
	httpClient  *http.Client
}

// NewMojaloopRail fails closed on incomplete config.
func NewMojaloopRail(baseURL, source, destination, payeeRef string, httpClient *http.Client) (*MojaloopRail, error) {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(source) == "" ||
		strings.TrimSpace(destination) == "" || strings.TrimSpace(payeeRef) == "" {
		return nil, errors.New("mojaloop base URL, FSPIOP source/destination and payee reference are required")
	}
	if source == destination {
		return nil, errors.New("FSPIOP source and destination must be distinct participants")
	}
	if httpClient == nil {
		return nil, errors.New("mojaloop http client is required")
	}
	return &MojaloopRail{
		baseURL: strings.TrimRight(baseURL, "/"), source: source,
		destination: destination, payeeRef: payeeRef, httpClient: httpClient,
	}, nil
}

// fspiopRequest builds one signed-headers FSPIOP request.
func (rail *MojaloopRail) fspiopRequest(ctx context.Context, method, path, contentType string, body []byte) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, rail.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", contentType)
	request.Header.Set("FSPIOP-Source", rail.source)
	request.Header.Set("FSPIOP-Destination", rail.destination)
	request.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	injectTraceContext(ctx, request)
	return request, nil
}

// Initiate runs the FSPIOP quoting -> transfer flow for one top-up. The
// quote response carries the hub-computed ILP packet + condition, which the
// transfer leg forwards verbatim (BlueFare never fabricates ILP material).
func (rail *MojaloopRail) Initiate(ctx context.Context, instruction RailInstruction) (RailInitiation, error) {
	ctx, span := tracer().Start(ctx, "ferry.rail.mojaloop.initiate")
	defer span.End()
	if instruction.Reference == "" || instruction.AmountNGNMinor <= 0 {
		return RailInitiation{}, errors.New("reference and positive amount are required")
	}
	quoteID := strings.ReplaceAll(instruction.Reference, "-", "")
	quoteBody, err := json.Marshal(map[string]any{
		"transactionId": quoteID,
		"payee":         map[string]any{"partyIdInfo": map[string]any{"partyIdType": "ALIAS", "partyIdentifier": rail.payeeRef}},
		"payer":         map[string]any{"partyIdInfo": map[string]any{"partyIdType": "ALIAS", "partyIdentifier": instruction.Reference}},
		"amountType":    "RECEIVE",
		"amount":        map[string]any{"amount": minorToMajorString(instruction.AmountNGNMinor), "currency": "NGN"},
	})
	if err != nil {
		return RailInitiation{}, err
	}
	quoteContent := "application/vnd.interoperability.quotes+json;version=1.0"
	quoteReq, err := rail.fspiopRequest(ctx, http.MethodPost, "/quotes", quoteContent, quoteBody)
	if err != nil {
		return RailInitiation{}, err
	}
	quoteResp, err := rail.httpClient.Do(quoteReq)
	if err != nil {
		return RailInitiation{}, fmt.Errorf("post FSPIOP quote: %w", err)
	}
	defer quoteResp.Body.Close()
	if quoteResp.StatusCode != http.StatusOK && quoteResp.StatusCode != http.StatusAccepted {
		return RailInitiation{}, fmt.Errorf("FSPIOP quote returned %d", quoteResp.StatusCode)
	}
	var quote struct {
		IlpPacket  string `json:"ilpPacket"`
		Condition  string `json:"condition"`
		Expiration string `json:"expiration"`
	}
	if err := json.NewDecoder(io.LimitReader(quoteResp.Body, 1<<20)).Decode(&quote); err != nil {
		return RailInitiation{}, fmt.Errorf("decode FSPIOP quote: %w", err)
	}
	if quote.IlpPacket == "" || quote.Condition == "" {
		return RailInitiation{}, errors.New("FSPIOP quote carried no ILP material (fail-closed)")
	}
	transferBody, err := json.Marshal(map[string]any{
		"transferId":   quoteID,
		"payerFsp":     rail.source,
		"payeeFsp":     rail.destination,
		"amount":       map[string]any{"amount": minorToMajorString(instruction.AmountNGNMinor), "currency": "NGN"},
		"ilpPacket":    quote.IlpPacket,
		"condition":    quote.Condition,
		"expiration":   quote.Expiration,
		"extensionList": map[string]any{"extension": []map[string]string{
			{"key": "bluefareReference", "value": instruction.Reference},
		}},
	})
	if err != nil {
		return RailInitiation{}, err
	}
	transferContent := "application/vnd.interoperability.transfers+json;version=1.0"
	transferReq, err := rail.fspiopRequest(ctx, http.MethodPost, "/transfers", transferContent, transferBody)
	if err != nil {
		return RailInitiation{}, err
	}
	transferResp, err := rail.httpClient.Do(transferReq)
	if err != nil {
		return RailInitiation{}, fmt.Errorf("post FSPIOP transfer: %w", err)
	}
	defer transferResp.Body.Close()
	if transferResp.StatusCode != http.StatusOK && transferResp.StatusCode != http.StatusAccepted {
		return RailInitiation{}, fmt.Errorf("FSPIOP transfer returned %d", transferResp.StatusCode)
	}
	return RailInitiation{ExternalRef: "mojaloop:" + quoteID}, nil
}

// ---------------------------------------------------------------------------
// NIP reference-credit adapter.
// ---------------------------------------------------------------------------

// NIPRail initiates an NIP-style reference credit: the durable top-up
// reference travels as the transfer narration (the payer echoes it; the
// verified webhook reconciles on it).
type NIPRail struct {
	baseURL     string
	apiKey      string
	accountName string
	httpClient  *http.Client
}

// NewNIPRail fails closed on incomplete config.
func NewNIPRail(baseURL, apiKey, accountName string, httpClient *http.Client) (*NIPRail, error) {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(apiKey) == "" || strings.TrimSpace(accountName) == "" {
		return nil, errors.New("NIP base URL, API key and receiving account name are required")
	}
	if httpClient == nil {
		return nil, errors.New("NIP http client is required")
	}
	return &NIPRail{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, accountName: accountName, httpClient: httpClient}, nil
}

// Initiate posts one reference-credit instruction.
func (rail *NIPRail) Initiate(ctx context.Context, instruction RailInstruction) (RailInitiation, error) {
	ctx, span := tracer().Start(ctx, "ferry.rail.nip.initiate")
	defer span.End()
	if instruction.Reference == "" || instruction.AmountNGNMinor <= 0 {
		return RailInitiation{}, errors.New("reference and positive amount are required")
	}
	body, err := json.Marshal(map[string]any{
		"reference":     instruction.Reference,
		"amountMinor":   instruction.AmountNGNMinor,
		"currency":      "NGN",
		"creditAccount": rail.accountName,
		"narration":     instruction.Reference, // the reconciliation echo
	})
	if err != nil {
		return RailInitiation{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rail.baseURL+"/transfers", bytes.NewReader(body))
	if err != nil {
		return RailInitiation{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+rail.apiKey)
	injectTraceContext(ctx, request)
	response, err := rail.httpClient.Do(request)
	if err != nil {
		return RailInitiation{}, fmt.Errorf("post NIP transfer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return RailInitiation{}, fmt.Errorf("NIP transfer returned %d", response.StatusCode)
	}
	var acknowledgement struct {
		TransactionRef string `json:"transactionRef"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&acknowledgement); err != nil {
		return RailInitiation{}, fmt.Errorf("decode NIP acknowledgement: %w", err)
	}
	if acknowledgement.TransactionRef == "" {
		return RailInitiation{}, errors.New("NIP acknowledgement carried no transaction reference (fail-closed)")
	}
	return RailInitiation{ExternalRef: "nip:" + acknowledgement.TransactionRef}, nil
}

// minorToMajorString renders minor units as a decimal string ("123" -> "1.23").
func minorToMajorString(minor int64) string {
	return fmt.Sprintf("%d.%02d", minor/100, minor%100)
}

// ---------------------------------------------------------------------------
// Env-gated factory (fail-closed on partial config).
// ---------------------------------------------------------------------------

// Rails bundles the live adapters by top-up channel.
type Rails map[string]RailClient

// LoadRailsFromEnv builds the live adapters. Each rail is all-or-nothing:
// when any of its env vars is set, ALL must be set (plus readable TLS
// material when TLS files are configured) — partial config fails boot.
// With no rail env at all the bundle is empty and rail-channel top-ups fail
// closed at request time with ErrRailNotConfigured.
func LoadRailsFromEnv() (Rails, error) {
	rails := Rails{}
	mojaloopVars := map[string]string{
		"FERRY_MOJALOOP_BASE_URL":           os.Getenv("FERRY_MOJALOOP_BASE_URL"),
		"FERRY_MOJALOOP_FSPIOP_SOURCE":      os.Getenv("FERRY_MOJALOOP_FSPIOP_SOURCE"),
		"FERRY_MOJALOOP_FSPIOP_DESTINATION": os.Getenv("FERRY_MOJALOOP_FSPIOP_DESTINATION"),
		"FERRY_MOJALOOP_PAYEE_REF":          os.Getenv("FERRY_MOJALOOP_PAYEE_REF"),
	}
	if anyEnvSet(mojaloopVars) {
		if err := requireAllEnv(mojaloopVars); err != nil {
			return nil, err
		}
		client, err := railHTTPClient(
			os.Getenv("FERRY_MOJALOOP_TLS_CERT_FILE"),
			os.Getenv("FERRY_MOJALOOP_TLS_KEY_FILE"),
			os.Getenv("FERRY_MOJALOOP_TLS_CA_FILE"))
		if err != nil {
			return nil, fmt.Errorf("mojaloop rail: %w", err)
		}
		rail, err := NewMojaloopRail(mojaloopVars["FERRY_MOJALOOP_BASE_URL"],
			mojaloopVars["FERRY_MOJALOOP_FSPIOP_SOURCE"], mojaloopVars["FERRY_MOJALOOP_FSPIOP_DESTINATION"],
			mojaloopVars["FERRY_MOJALOOP_PAYEE_REF"], client)
		if err != nil {
			return nil, err
		}
		rails[TopUpMojaloop] = rail
	}
	nipVars := map[string]string{
		"FERRY_NIP_BASE_URL":       os.Getenv("FERRY_NIP_BASE_URL"),
		"FERRY_NIP_API_KEY_FILE":   os.Getenv("FERRY_NIP_API_KEY_FILE"),
		"FERRY_NIP_ACCOUNT_NAME":   os.Getenv("FERRY_NIP_ACCOUNT_NAME"),
	}
	if anyEnvSet(nipVars) {
		if err := requireAllEnv(nipVars); err != nil {
			return nil, err
		}
		apiKey, err := readSecretFile(os.Getenv("FERRY_NIP_API_KEY_FILE"))
		if err != nil {
			return nil, fmt.Errorf("NIP rail: %w", err)
		}
		client, err := railHTTPClient(
			os.Getenv("FERRY_NIP_TLS_CERT_FILE"),
			os.Getenv("FERRY_NIP_TLS_KEY_FILE"),
			os.Getenv("FERRY_NIP_TLS_CA_FILE"))
		if err != nil {
			return nil, fmt.Errorf("NIP rail: %w", err)
		}
		rail, err := NewNIPRail(nipVars["FERRY_NIP_BASE_URL"], apiKey, nipVars["FERRY_NIP_ACCOUNT_NAME"], client)
		if err != nil {
			return nil, err
		}
		rails[TopUpNIPTransfer] = rail
	}
	return rails, nil
}

func anyEnvSet(vars map[string]string) bool {
	for _, value := range vars {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func requireAllEnv(vars map[string]string) error {
	for name, value := range vars {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("partial rail config: %s is required when any rail var is set (fail-closed)", name)
		}
	}
	return nil
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", path, err)
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 8 {
		return "", errors.New("rail API key is too short (fail-closed)")
	}
	return secret, nil
}
