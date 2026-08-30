package fare

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// tracedContext carries one valid (sampled) span context so trace-context
// propagation has something real to serialize.
func tracedContext() context.Context {
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x0a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		SpanID:     trace.SpanID{0x0b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		TraceFlags: trace.FlagsSampled,
	})
	return trace.ContextWithSpanContext(context.Background(), spanContext)
}

// PRA-134 unit tests: REAL client flows against test-spawned HTTP servers
// speaking FSPIOP / NIP — headers, bodies, trace-context, error paths.

type fspiopServer struct {
	t            *testing.T
	mu           sync.Mutex
	quoteHeaders http.Header
	transferBody map[string]any
}

func (server *fspiopServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /quotes", func(writer http.ResponseWriter, request *http.Request) {
		server.mu.Lock()
		server.quoteHeaders = request.Header.Clone()
		server.mu.Unlock()
		writer.Header().Set("Content-Type", "application/vnd.interoperability.quotes+json;version=1.0")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"ilpPacket":  "AYICgQAAAAAAAAPoFW5YdG1hLmJsdWVmYXJl",
			"condition":  "f5sqb7TBOWMbHDGIcZRIJKm1RWa4LRCzVaxEoLC0gZs",
			"expiration": "2030-01-01T00:00:00Z",
		})
	})
	mux.HandleFunc("POST /transfers", func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		server.mu.Lock()
		server.transferBody = body
		server.mu.Unlock()
		writer.Header().Set("Content-Type", "application/vnd.interoperability.transfers+json;version=1.0")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(map[string]any{"fulfilment": "WLctttbu2HvTsa1XWvUoGRcQozH529euKcSmOfWfOZo"})
	})
	return mux
}

func TestMojaloopRailRealFlow(t *testing.T) {
	server := &fspiopServer{t: t}
	spawner := httptest.NewServer(server.handler())
	defer spawner.Close()
	rail, err := NewMojaloopRail(spawner.URL, "bluefare", "hub", "bluefare-alias", spawner.Client())
	if err != nil {
		t.Fatal(err)
	}
	initiation, err := rail.Initiate(tracedContext(), RailInstruction{
		Reference: "BFM-0123456789ABCDEF", AmountNGNMinor: 50000, Narration: "BFM-0123456789ABCDEF",
	})
	if err != nil {
		t.Fatal(err)
	}
	if initiation.ExternalRef != "mojaloop:BFM0123456789ABCDEF" {
		t.Fatalf("external ref = %q", initiation.ExternalRef)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	// FSPIOP discipline: source/destination + versioned content type.
	if server.quoteHeaders.Get("FSPIOP-Source") != "bluefare" || server.quoteHeaders.Get("FSPIOP-Destination") != "hub" {
		t.Fatalf("FSPIOP headers = %v", server.quoteHeaders)
	}
	if !strings.Contains(server.quoteHeaders.Get("Content-Type"), "interoperability.quotes+json;version=1.0") {
		t.Fatalf("quote content type = %q", server.quoteHeaders.Get("Content-Type"))
	}
	// Trace-context propagation (W3C traceparent header present on the wire).
	if server.quoteHeaders.Get("Traceparent") == "" {
		t.Fatal("traceparent must propagate to the rail (span-links discipline)")
	}
	// The transfer leg forwards the hub's ILP material verbatim and binds
	// the durable reference in the extension list.
	if server.transferBody["ilpPacket"] == "" || server.transferBody["condition"] == "" {
		t.Fatalf("transfer body missing ILP material: %v", server.transferBody)
	}
	extensions := server.transferBody["extensionList"].(map[string]any)["extension"].([]any)
	found := false
	for _, extension := range extensions {
		pair := extension.(map[string]any)
		if pair["key"] == "bluefareReference" && pair["value"] == "BFM-0123456789ABCDEF" {
			found = true
		}
	}
	if !found {
		t.Fatalf("transfer extensions = %v", extensions)
	}
}

func TestMojaloopRailFailsClosedOnQuoteWithoutILP(t *testing.T) {
	spawner := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"transferAmount": map[string]any{"amount": "500.00"}})
	}))
	defer spawner.Close()
	rail, err := NewMojaloopRail(spawner.URL, "bluefare", "hub", "bluefare-alias", spawner.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rail.Initiate(tracedContext(), RailInstruction{Reference: "BFM-X", AmountNGNMinor: 50000}); err == nil {
		t.Fatal("quote without ILP material must fail closed")
	}
	if _, err := NewMojaloopRail(spawner.URL, "same", "same", "alias", spawner.Client()); err == nil {
		t.Fatal("identical source/destination must fail closed")
	}
	if _, err := NewMojaloopRail("", "a", "b", "c", spawner.Client()); err == nil {
		t.Fatal("missing base URL must fail closed")
	}
}

func TestNIPRailRealFlow(t *testing.T) {
	var authHeader, body string
	spawner := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authHeader = request.Header.Get("Authorization")
		raw, _ := io.ReadAll(request.Body)
		body = string(raw)
		if request.Header.Get("Traceparent") == "" {
			t.Error("traceparent must propagate")
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"transactionRef": "NIP-TXN-99"})
	}))
	defer spawner.Close()
	rail, err := NewNIPRail(spawner.URL, "test-api-key-12345", "BLUEFARE-COLLECTION", spawner.Client())
	if err != nil {
		t.Fatal(err)
	}
	initiation, err := rail.Initiate(tracedContext(), RailInstruction{
		Reference: "BFN-0123456789ABCDEF", AmountNGNMinor: 75000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if initiation.ExternalRef != "nip:NIP-TXN-99" {
		t.Fatalf("external ref = %q", initiation.ExternalRef)
	}
	if authHeader != "Bearer test-api-key-12345" {
		t.Fatalf("authorization = %q", authHeader)
	}
	if !strings.Contains(body, `"narration":"BFN-0123456789ABCDEF"`) ||
		!strings.Contains(body, `"amountMinor":75000`) {
		t.Fatalf("body = %s", body)
	}
}

func TestNIPRailFailsClosed(t *testing.T) {
	spawner := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"status": "ok"}) // no transactionRef
	}))
	defer spawner.Close()
	rail, err := NewNIPRail(spawner.URL, "key-12345678", "ACCOUNT", spawner.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rail.Initiate(tracedContext(), RailInstruction{Reference: "BFN-X", AmountNGNMinor: 1000}); err == nil {
		t.Fatal("acknowledgement without a transaction reference must fail closed")
	}
}

func TestLoadRailsFromEnvFailClosed(t *testing.T) {
	// Partial Mojaloop config fails boot.
	t.Setenv("FERRY_MOJALOOP_BASE_URL", "https://switch.example")
	t.Setenv("FERRY_MOJALOOP_FSPIOP_SOURCE", "bluefare")
	if _, err := LoadRailsFromEnv(); err == nil {
		t.Fatal("partial mojaloop config must fail closed")
	}
}

func TestLoadRailsFromEnvEmpty(t *testing.T) {
	rails, err := LoadRailsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(rails) != 0 {
		t.Fatalf("empty env must yield no adapters, got %d", len(rails))
	}
}
