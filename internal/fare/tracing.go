package fare

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracer returns the package tracer for the BlueFare money-movement spans
// (pass saga, fare-capping transaction, offline-debit settlement). With
// telemetry disabled the global provider is a no-op: spans are non-recording
// and the business path is unaffected (sanctioned fail-open telemetry).
func tracer() trace.Tracer {
	return otel.Tracer("github.com/munisp/blueeconomy-ferry-ticketing/internal/fare")
}
