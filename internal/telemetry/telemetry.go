// Package telemetry wires OpenTelemetry tracing and Prometheus metrics for
// the service. Telemetry is environment-configured and follows the service's
// fail-closed posture: malformed or contradictory configuration is a startup
// error. Tracing is disabled by default; a disabled service runs an explicit
// no-op tracer and still serves local Prometheus metrics on GET /metrics.
//
// Export is the platform's one sanctioned fail-open (OTEL_DESIGN §1): the
// OTLP exporter is async/batched and non-blocking, and an unreachable
// collector means spans are dropped with the telemetry_dropped_total counter
// incremented — never a request failure.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config is the validated telemetry configuration. Enabled is false when no
// OTLP endpoint is configured; every other field is then ignored.
type Config struct {
	Enabled     bool
	Endpoint    string
	Insecure    bool
	ServiceName string
}

// LoadConfig reads OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_INSECURE,
// OTEL_SERVICE_NAME and OTEL_SDK_DISABLED. An absent endpoint means tracing is
// disabled; a present but malformed endpoint, an unknown boolean value, or a
// contradictory OTEL_SDK_DISABLED=true fails closed.
func LoadConfig(serviceName string) (Config, error) {
	if strings.TrimSpace(serviceName) == "" {
		return Config{}, errors.New("telemetry service name is required")
	}
	config := Config{ServiceName: serviceName}
	if override := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); override != "" {
		if len(override) > 128 {
			return Config{}, errors.New("OTEL_SERVICE_NAME must be at most 128 characters")
		}
		config.ServiceName = override
	}
	disabled, err := parseBoolean("OTEL_SDK_DISABLED")
	if err != nil {
		return Config{}, err
	}
	insecure, err := parseBoolean("OTEL_EXPORTER_OTLP_INSECURE")
	if err != nil {
		return Config{}, err
	}
	config.Insecure = insecure
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if disabled {
		if endpoint != "" {
			return Config{}, errors.New("OTEL_SDK_DISABLED=true conflicts with OTEL_EXPORTER_OTLP_ENDPOINT; remove one (fail-closed)")
		}
		return config, nil
	}
	if endpoint == "" {
		return config, nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT must be a host:port pair without scheme, credentials or path: %q", endpoint)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT has an invalid port: %q", endpoint)
	}
	config.Enabled = true
	config.Endpoint = endpoint
	return config, nil
}

// parseBoolean accepts only empty, "true" or "false"; anything else fails
// closed rather than being silently interpreted.
func parseBoolean(name string) (bool, error) {
	switch value := strings.TrimSpace(os.Getenv(name)); value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false when set", name)
	}
}

// Propagator is the platform propagation contract: W3C tracecontext plus
// baggage (tenant.id and agency ride baggage from the edge to every server
// span).
func Propagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
}

// dropCountingExporter wraps the OTLP exporter so a collector outage is a
// drop-with-metric event (telemetry_dropped_total), never a request error.
type dropCountingExporter struct {
	wrapped sdktrace.SpanExporter
	onDrop  func(spans int64)
}

func (exporter dropCountingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if err := exporter.wrapped.ExportSpans(ctx, spans); err != nil {
		exporter.onDrop(int64(len(spans)))
		return err
	}
	return nil
}

func (exporter dropCountingExporter) Shutdown(ctx context.Context) error {
	return exporter.wrapped.Shutdown(ctx)
}

// Telemetry carries the tracer, the Prometheus meter pipeline and the HTTP
// middleware. It is safe to use a zero-capacity instance only through Setup.
type Telemetry struct {
	config         Config
	tracer         trace.Tracer
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	metricsHandler http.Handler
	requests       metric.Int64Counter
	duration       metric.Float64Histogram
	dropped        metric.Int64Counter
	droppedTotal   atomic.Int64
}

// Setup builds the meter and tracer pipelines. The Prometheus exporter is
// always local-only (no egress) and is installed even when tracing is
// disabled; the OTLP gRPC trace exporter is created only when enabled.
func Setup(ctx context.Context, config Config) (*Telemetry, error) {
	if strings.TrimSpace(config.ServiceName) == "" {
		return nil, errors.New("telemetry service name is required")
	}
	serviceResource := resource.NewSchemaless(attribute.String("service.name", config.ServiceName))
	meterProvider, metricsHandler, err := newMeterPipeline(serviceResource)
	if err != nil {
		return nil, err
	}
	meter := meterProvider.Meter(config.ServiceName)
	requests, err := meter.Int64Counter("http.server.requests", metric.WithDescription("HTTP requests partitioned by method, route and status code"))
	if err != nil {
		return nil, fmt.Errorf("create request counter: %w", err)
	}
	duration, err := meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"), metric.WithDescription("HTTP request duration in seconds"))
	if err != nil {
		return nil, fmt.Errorf("create duration histogram: %w", err)
	}
	dropped, err := meter.Int64Counter("telemetry_dropped_total", metric.WithDescription("Telemetry spans dropped because the collector was unreachable (sanctioned fail-open)"))
	if err != nil {
		return nil, fmt.Errorf("create dropped telemetry counter: %w", err)
	}
	telemetry := &Telemetry{
		config:         config,
		meterProvider:  meterProvider,
		metricsHandler: metricsHandler,
		requests:       requests,
		duration:       duration,
		dropped:        dropped,
	}
	// Propagation is installed even when tracing is disabled: inject/extract
	// round-trips must behave identically in both modes (Kafka carriers,
	// outbound HTTP headers) so upstream spans still flow through unchanged.
	otel.SetTextMapPropagator(Propagator())
	if !config.Enabled {
		telemetry.tracer = noop.NewTracerProvider().Tracer(config.ServiceName)
		return telemetry, nil
	}
	exporterOptions := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(config.Endpoint)}
	if config.Insecure {
		exporterOptions = append(exporterOptions, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(ctx, exporterOptions...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP gRPC trace exporter: %w", err)
	}
	// Async/batched, non-blocking export; collector-down is counted via
	// telemetry_dropped_total by the wrapping exporter (drop-with-metric).
	telemetry.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(dropCountingExporter{wrapped: exporter, onDrop: telemetry.recordDropped}),
		sdktrace.WithResource(serviceResource),
	)
	otel.SetTracerProvider(telemetry.tracerProvider)
	telemetry.tracer = telemetry.tracerProvider.Tracer(config.ServiceName)
	return telemetry, nil
}

// recordDropped counts spans dropped on export failure (collector down).
func (telemetry *Telemetry) recordDropped(spans int64) {
	telemetry.droppedTotal.Add(spans)
	telemetry.dropped.Add(context.Background(), spans)
}

// DroppedTotal reports the lifetime count of spans dropped on export
// failure. It is the in-process view of telemetry_dropped_total.
func (telemetry *Telemetry) DroppedTotal() int64 {
	return telemetry.droppedTotal.Load()
}

// newMeterPipeline installs a Prometheus reader on a private registry so
// repeated Setup calls (tests, in-process binaries) never collide on the
// global Prometheus registry.
func newMeterPipeline(serviceResource *resource.Resource) (*sdkmetric.MeterProvider, http.Handler, error) {
	registry := prometheus.NewRegistry()
	reader, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, fmt.Errorf("create Prometheus exporter: %w", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(serviceResource))
	return provider, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), nil
}

// Enabled reports whether OTLP trace export is active.
func (telemetry *Telemetry) Enabled() bool {
	return telemetry.config.Enabled
}

// Tracer returns the service tracer: the OTLP-backed SDK tracer when enabled,
// otherwise the explicit no-op tracer.
func (telemetry *Telemetry) Tracer() trace.Tracer {
	return telemetry.tracer
}

// Meter returns a meter on the service meter pipeline (exported through the
// local Prometheus endpoint), for non-HTTP components such as the met-ocean
// bridge consumer.
func (telemetry *Telemetry) Meter() metric.Meter {
	return telemetry.meterProvider.Meter(telemetry.config.ServiceName)
}

// MetricsHandler serves the Prometheus scrape endpoint.
func (telemetry *Telemetry) MetricsHandler() http.Handler {
	return telemetry.metricsHandler
}

// Shutdown flushes and stops both providers.
func (telemetry *Telemetry) Shutdown(ctx context.Context) error {
	var shutdownErr error
	if telemetry.tracerProvider != nil {
		shutdownErr = telemetry.tracerProvider.Shutdown(ctx)
	}
	if telemetry.meterProvider != nil {
		if err := telemetry.meterProvider.Shutdown(ctx); shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// statusRecorder captures the response status code for span attributes and
// metrics without changing response semantics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
}

// Middleware traces and meters every request. The outer otelhttp handler
// extracts the W3C traceparent/baggage context and starts the server span;
// the inner wrapper renames the span to the matched route pattern
// (http.Request.Pattern) once the ServeMux has routed, so metric labels and
// span names never carry raw paths or identifiers. Unmatched routes are
// labelled "unmatched". tenant.id and agency baggage members become span
// attributes (never metric labels — metrics stay low-cardinality).
func (telemetry *Telemetry) Middleware(next http.Handler) http.Handler {
	inner := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		ctx := request.Context()
		span := trace.SpanFromContext(ctx)
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		route := request.Pattern
		if route == "" {
			route = "unmatched"
		} else {
			span.SetName(route)
		}
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
		// Tenant attribution: edge-injected baggage → span attributes.
		if member := baggage.FromContext(ctx).Member("tenant.id"); member.Value() != "" {
			span.SetAttributes(attribute.String("tenant.id", member.Value()))
		}
		if member := baggage.FromContext(ctx).Member("agency"); member.Value() != "" {
			span.SetAttributes(attribute.String("agency", member.Value()))
		}
		if recorder.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(recorder.status))
		}
		metricAttributes := metric.WithAttributes(
			attribute.String("http.request.method", request.Method),
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
		telemetry.requests.Add(ctx, 1, metricAttributes)
		telemetry.duration.Record(ctx, time.Since(started).Seconds(), metricAttributes)
	})
	options := []otelhttp.Option{
		otelhttp.WithPropagators(Propagator()),
		// otelhttp applies the formatter after the handler returns, once the
		// ServeMux has recorded the matched pattern on the request: name the
		// span by route pattern, falling back to the bare method pre-routing.
		otelhttp.WithSpanNameFormatter(func(_ string, request *http.Request) string {
			if request.Pattern != "" {
				return request.Pattern
			}
			return request.Method
		}),
	}
	if telemetry.tracerProvider != nil {
		options = append(options, otelhttp.WithTracerProvider(telemetry.tracerProvider))
	}
	return otelhttp.NewHandler(inner, "http.server", options...)
}

// HTTPTransport wraps an outbound RoundTripper with otelhttp client tracing:
// every outbound HTTP call becomes a CLIENT span and the live traceparent +
// baggage are injected into the request headers. A nil base wraps
// http.DefaultTransport.
func HTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}
