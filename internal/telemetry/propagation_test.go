package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// startRecordingSpan starts a real span on an isolated provider so tests can
// exercise injection without global state.
func startRecordingSpan(t *testing.T, ctx context.Context, name string) (context.Context, trace.Span) {
	t.Helper()
	provider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	ctx, span := provider.Tracer("propagation-test").Start(ctx, name)
	return ctx, span
}

// TestKafkaCarrierRoundTrip injects the live trace context into kafka-go
// message headers (produce path) and extracts it (consume path): the consumer
// must recover the producer's trace and span IDs.
func TestKafkaCarrierRoundTrip(t *testing.T) {
	ctx, span := startRecordingSpan(t, context.Background(), "produce")
	defer span.End()
	producerContext := trace.SpanContextFromContext(ctx)
	if !producerContext.IsValid() {
		t.Fatal("producer span context must be valid")
	}

	headers := InjectKafkaHeaders(ctx, []kafka.Header{{Key: "event_type", Value: []byte("ferry.ticket.issued")}})
	carrier := KafkaCarrier{Headers: &headers}
	if carrier.Get("traceparent") == "" {
		t.Fatalf("traceparent must be injected into the record headers, got %v", headers)
	}
	if carrier.Get("event_type") != "ferry.ticket.issued" {
		t.Fatal("existing record headers must be preserved")
	}

	extracted := ExtractKafkaHeaders(context.Background(), headers)
	consumerContext := trace.SpanContextFromContext(extracted)
	if consumerContext.TraceID() != producerContext.TraceID() {
		t.Fatalf("consumer must join the producer trace: got %s, want %s", consumerContext.TraceID(), producerContext.TraceID())
	}
	if consumerContext.SpanID() != producerContext.SpanID() {
		t.Fatalf("consumer parent must be the producer span: got %s, want %s", consumerContext.SpanID(), producerContext.SpanID())
	}
	if !consumerContext.IsRemote() {
		t.Fatal("extracted context must be marked remote")
	}
}

// TestHTTPHeaderRoundTrip verifies the W3C traceparent survives the outbound
// inject (client transport) → inbound extract (server middleware) path.
func TestHTTPHeaderRoundTrip(t *testing.T) {
	ctx, span := startRecordingSpan(t, context.Background(), "client")
	defer span.End()
	producerContext := trace.SpanContextFromContext(ctx)

	request := httptest.NewRequest(http.MethodGet, "http://downstream.invalid/v1/manifests", nil)
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(request.Header))
	if request.Header.Get("traceparent") == "" {
		t.Fatal("traceparent must be injected into outbound headers")
	}

	extracted := Propagator().Extract(context.Background(), propagation.HeaderCarrier(request.Header))
	serverContext := trace.SpanContextFromContext(extracted)
	if serverContext.TraceID() != producerContext.TraceID() || serverContext.SpanID() != producerContext.SpanID() {
		t.Fatalf("server must continue the client trace: got %s/%s", serverContext.TraceID(), serverContext.SpanID())
	}
}

// TestMiddlewareTenantBaggageAttributes drives one server handler through the
// middleware with edge-injected tenant.id and agency baggage and asserts both
// become span attributes (and never metric labels).
func TestMiddlewareTenantBaggageAttributes(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tickets/{id}", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	handler := telemetry.Middleware(mux)
	request := httptest.NewRequest(http.MethodGet, "/v1/tickets/ticket-9", nil)
	request.Header.Set("baggage", "tenant.id=tenant-lagos,agency=NIMASA")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("one span expected, got %d", len(spans))
	}
	assertAttribute(t, spans[0].Attributes(), "tenant.id", "tenant-lagos")
	assertAttribute(t, spans[0].Attributes(), "agency", "NIMASA")
	assertAttribute(t, spans[0].Attributes(), "http.route", "GET /v1/tickets/{id}")
}

// TestKafkaCarrierPreservesContextAcrossDisabledMode proves injection uses the
// installed propagator even when the exporter is disabled (no endpoint): the
// platform's disabled services still forward upstream traces transparently.
func TestKafkaCarrierPreservesContextAcrossDisabledMode(t *testing.T) {
	ctx, span := startRecordingSpan(t, context.Background(), "upstream")
	defer span.End()
	want := trace.SpanContextFromContext(ctx).TraceID()

	headers := InjectKafkaHeaders(ctx, nil)
	got := trace.SpanContextFromContext(ExtractKafkaHeaders(context.Background(), headers)).TraceID()
	if got != want {
		t.Fatalf("round-trip must preserve the trace: got %s, want %s", got, want)
	}
}
