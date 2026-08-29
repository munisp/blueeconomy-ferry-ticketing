package telemetry

import (
	"context"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/propagation"
)

// KafkaCarrier adapts kafka-go message headers to a TextMapCarrier so the
// W3C traceparent/baggage context rides every produced record and is
// recovered on consume (OTEL_DESIGN §2 — kafka-go has no auto-instrumentation,
// so carriers are manual).
type KafkaCarrier struct {
	Headers *[]kafka.Header
}

// Get returns the first header value for key.
func (carrier KafkaCarrier) Get(key string) string {
	if carrier.Headers == nil {
		return ""
	}
	for _, header := range *carrier.Headers {
		if header.Key == key {
			return string(header.Value)
		}
	}
	return ""
}

// Set appends (or replaces) the header for key.
func (carrier KafkaCarrier) Set(key, value string) {
	if carrier.Headers == nil {
		return
	}
	for index, header := range *carrier.Headers {
		if header.Key == key {
			(*carrier.Headers)[index].Value = []byte(value)
			return
		}
	}
	*carrier.Headers = append(*carrier.Headers, kafka.Header{Key: key, Value: []byte(value)})
}

// Keys lists the header keys present.
func (carrier KafkaCarrier) Keys() []string {
	if carrier.Headers == nil {
		return nil
	}
	keys := make([]string, 0, len(*carrier.Headers))
	for _, header := range *carrier.Headers {
		keys = append(keys, header.Key)
	}
	return keys
}

// InjectKafkaHeaders returns headers with the live trace context injected.
// The input slice is never mutated; pass its result to the produce call.
func InjectKafkaHeaders(ctx context.Context, headers []kafka.Header) []kafka.Header {
	carrier := KafkaCarrier{Headers: &headers}
	propagator().Inject(ctx, carrier)
	return headers
}

// ExtractKafkaHeaders recovers the remote trace context carried by a consumed
// record. The returned context is the parent for every consumer span.
func ExtractKafkaHeaders(ctx context.Context, headers []kafka.Header) context.Context {
	return propagator().Extract(ctx, KafkaCarrier{Headers: &headers})
}

// propagator resolves the platform propagation contract. Setup installs the
// same composite globally; carriers use the contract directly so injection
// behaves identically before/without Setup (tests, one-shot binaries) — the
// otel global default is an empty no-op composite and must not be consulted.
func propagator() propagation.TextMapPropagator {
	return Propagator()
}
