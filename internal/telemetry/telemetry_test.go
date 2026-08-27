package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestLoadConfigDefaultsToDisabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	config, err := LoadConfig("blueeconomy-ferry-ticketing")
	if err != nil {
		t.Fatalf("default config must load: %v", err)
	}
	if config.Enabled {
		t.Fatal("tracing must default to disabled when no endpoint is configured")
	}
	if config.ServiceName != "blueeconomy-ferry-ticketing" {
		t.Fatalf("service name must default to the binary identity, got %q", config.ServiceName)
	}
}

func TestLoadConfigAcceptsEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.ops.svc:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_SERVICE_NAME", "")
	config, err := LoadConfig("blueeconomy-ferry-ticketing")
	if err != nil {
		t.Fatalf("valid endpoint must load: %v", err)
	}
	if !config.Enabled || config.Endpoint != "otel-collector.ops.svc:4317" || !config.Insecure {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestLoadConfigFailsClosedOnMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		envs map[string]string
	}{
		{"endpoint with scheme", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.invalid:4317"}},
		{"endpoint without port", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.invalid"}},
		{"endpoint with bad port", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector.example.invalid:not-a-port"}},
		{"endpoint with credentials", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "user:secret@collector:4317"}},
		{"disabled flag garbage", map[string]string{"OTEL_SDK_DISABLED": "yes"}},
		{"insecure flag garbage", map[string]string{"OTEL_EXPORTER_OTLP_INSECURE": "1"}},
		{"conflicting disabled and endpoint", map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_SDK_DISABLED", "")
			t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
			for name, value := range testCase.envs {
				t.Setenv(name, value)
			}
			if _, err := LoadConfig("blueeconomy-ferry-ticketing"); err == nil {
				t.Fatalf("case %q must fail closed", testCase.name)
			}
		})
	}
}

// testTelemetry builds a Telemetry backed by an in-memory span recorder and a
// real Prometheus pipeline, mirroring Setup without any network dependency.
func testTelemetry(t *testing.T) (*Telemetry, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	meterProvider, metricsHandler, err := newMeterPipeline(resource.NewSchemaless(attribute.String("service.name", "telemetry-test")))
	if err != nil {
		t.Fatalf("meter pipeline: %v", err)
	}
	meter := meterProvider.Meter("telemetry-test")
	requests, err := meter.Int64Counter("http.server.requests")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	duration, err := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("histogram: %v", err)
	}
	telemetry := &Telemetry{
		config:         Config{ServiceName: "telemetry-test", Enabled: true},
		tracer:         tracerProvider.Tracer("telemetry-test"),
		tracerProvider: tracerProvider,
		meterProvider:  meterProvider,
		metricsHandler: metricsHandler,
		requests:       requests,
		duration:       duration,
	}
	t.Cleanup(func() { _ = telemetry.Shutdown(context.Background()) })
	return telemetry, recorder
}

func TestMiddlewareCreatesSpanWithRouteAndStatus(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tickets/{id}/refund", func(writer http.ResponseWriter, request *http.Request) {
		if !trace.SpanFromContext(request.Context()).IsRecording() {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusForbidden)
	})
	handler := telemetry.Middleware(mux)
	request := httptest.NewRequest(http.MethodPost, "/v1/tickets/ticket-1/refund", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status must pass through unchanged, got %d", response.Code)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("exactly one span must be recorded, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "POST /v1/tickets/{id}/refund" {
		t.Fatalf("span must be renamed to the matched route, got %q", span.Name())
	}
	attributes := span.Attributes()
	assertAttribute(t, attributes, "http.route", "POST /v1/tickets/{id}/refund")
	assertAttribute(t, attributes, "http.response.status_code", int64(http.StatusForbidden))
}

func TestMiddlewareLabelsUnmatchedRoutes(t *testing.T) {
	telemetry, recorder := testTelemetry(t)
	handler := telemetry.Middleware(http.NotFoundHandler())
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nope", nil))
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("one span expected, got %d", len(spans))
	}
	assertAttribute(t, spans[0].Attributes(), "http.route", "unmatched")
}

func TestMetricsHandlerServesRequestMetrics(t *testing.T) {
	telemetry, _ := testTelemetry(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	handler := telemetry.Middleware(mux)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	response := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics handler must serve 200, got %d", response.Code)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "http_server_requests_total") {
		t.Fatal("request counter must be exported")
	}
	if !strings.Contains(text, "http_server_request_duration_seconds") {
		t.Fatal("duration histogram must be exported")
	}
	if !strings.Contains(text, `http_route="GET /healthz"`) {
		t.Fatal("metrics must carry the route label")
	}
}

func TestDisabledSetupNoopsAndServesMetrics(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_SDK_DISABLED", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	config, err := LoadConfig("blueeconomy-ferry-ticketing")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	telemetry, err := Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("disabled setup must succeed: %v", err)
	}
	if telemetry.Enabled() {
		t.Fatal("telemetry must report disabled")
	}
	handler := telemetry.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		span := trace.SpanFromContext(request.Context())
		if span.IsRecording() {
			t.Error("disabled mode must use a no-op, non-recording span")
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	response := httptest.NewRecorder()
	telemetry.MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatal("metrics must be served even when tracing is disabled")
	}
	if err := telemetry.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func assertAttribute(t *testing.T, attributes []attribute.KeyValue, key string, expected any) {
	t.Helper()
	for _, item := range attributes {
		if string(item.Key) != key {
			continue
		}
		switch want := expected.(type) {
		case string:
			if item.Value.AsString() == want {
				return
			}
		case int64:
			if item.Value.AsInt64() == want {
				return
			}
		}
		t.Fatalf("attribute %s has unexpected value %v (want %v)", key, item.Value, expected)
	}
	t.Fatalf("attribute %s missing from %v", key, attributes)
}
