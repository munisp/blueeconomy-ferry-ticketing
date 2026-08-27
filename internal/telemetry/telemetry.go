// Package telemetry wires OpenTelemetry tracing and Prometheus metrics for
// the service. Telemetry is environment-configured and follows the service's
// fail-closed posture: malformed or contradictory configuration is a startup
// error. Tracing is disabled by default; a disabled service runs an explicit
// no-op tracer and still serves local Prometheus metrics on GET /metrics.
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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
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
	telemetry := &Telemetry{
		config:         config,
		meterProvider:  meterProvider,
		metricsHandler: metricsHandler,
		requests:       requests,
		duration:       duration,
	}
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
	telemetry.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(serviceResource),
	)
	otel.SetTracerProvider(telemetry.tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	telemetry.tracer = telemetry.tracerProvider.Tracer(config.ServiceName)
	return telemetry, nil
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

// Middleware traces and meters every request. The span starts under the HTTP
// method and is renamed to the matched route pattern (http.Request.Pattern)
// once the ServeMux has routed, so metric labels never carry raw paths or
// identifiers. Unmatched routes are labelled "unmatched".
func (telemetry *Telemetry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		ctx, span := telemetry.tracer.Start(request.Context(), request.Method,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", request.Method)))
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		// WithContext shallow-copies the request; the ServeMux records the
		// matched route pattern on that copy, so read it back from there.
		routed := request.WithContext(ctx)
		next.ServeHTTP(recorder, routed)
		route := routed.Pattern
		if route == "" {
			route = "unmatched"
		} else {
			span.SetName(route)
		}
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
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
		span.End()
	})
}
