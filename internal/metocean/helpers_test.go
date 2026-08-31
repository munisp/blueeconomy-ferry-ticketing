package metocean

import (
	"time"

	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
)

const (
	waitTimeout  = 5 * time.Second
	pollInterval = 10 * time.Millisecond
)

// testSeed is the producer reference test seed (32 bytes of 0x29).
func testSeed() []byte {
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = 41
	}
	return seed
}

func noopTracer() trace.Tracer { return nooptrace.NewTracerProvider().Tracer("test") }

func noopMeter() metric.Meter { return noopmetric.NewMeterProvider().Meter("test") }
