package metocean

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

// DLQ header names carried on dead-lettered messages.
const (
	HeaderDLQReason      = "x-dlq-reason"
	HeaderDLQSourceTopic = "x-dlq-source-topic"
	HeaderDLQPartition   = "x-dlq-partition"
	HeaderDLQOffset      = "x-dlq-offset"
	HeaderDLQOriginalKey = "x-dlq-original-key"
)

// Bridge-level rejection reasons (the normative signature-scheme reasons
// come from provenance.Rejection).
const (
	ReasonMalformedAdvisory = "malformed-advisory"
	ReasonUnmappedZone      = "unmapped-zone"
	ReasonDispatchFailed    = "dispatch-failed"
)

// Header is one Kafka message header.
type Header struct {
	Key   string
	Value []byte
}

// Message is one consumed Kafka record.
type Message struct {
	Key       []byte
	Value     []byte
	Headers   []Header
	Topic     string
	Partition int
	Offset    int64
}

// MessageSource reads records from the advisory topic inside the consumer
// group. kafka-go provides the production implementation; tests substitute
// fakes. Fetch blocks until a record arrives or ctx is cancelled.
type MessageSource interface {
	Fetch(ctx context.Context) (Message, error)
	Commit(ctx context.Context, message Message) error
	Close() error
}

// Sink publishes dead-lettered records. kafka-go provides the production
// implementation; tests substitute fakes.
type Sink interface {
	Publish(ctx context.Context, key, value []byte, headers []Header) error
	Close() error
}

// Dispatcher applies one verified, parsed advisory to the operational
// domain (the Temporal bridge in production).
type Dispatcher interface {
	Dispatch(ctx context.Context, advisory Advisory) error
}

// UnmappedZoneError reports an advisory for a hazard zone the deployment
// does not map to ferry routes. It is dead-lettered explicitly: never
// silently dropped, never guessed.
type UnmappedZoneError struct{ ZoneID string }

// Error implements error.
func (err *UnmappedZoneError) Error() string {
	return fmt.Sprintf("hazard zone %q is not mapped to any ferry route", err.ZoneID)
}

// headerCarrier adapts message headers to the W3C propagation carrier for
// traceparent extraction.
type headerCarrier []Header

func (carrier headerCarrier) Get(key string) string {
	for _, header := range carrier {
		if header.Key == key {
			return string(header.Value)
		}
	}
	return ""
}

func (carrier headerCarrier) Set(key, value string) { /* extraction only */ }

func (carrier headerCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for _, header := range carrier {
		keys = append(keys, header.Key)
	}
	return keys
}

// Metrics groups the bridge counters.
type Metrics struct {
	consumed   metric.Int64Counter
	rejected   metric.Int64Counter
	dlq        metric.Int64Counter
	dispatched metric.Int64Counter
	skipped    metric.Int64Counter
}

// NewMetrics registers the bridge counters on meter.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	if meter == nil {
		return nil, errors.New("metric meter is required")
	}
	metrics := &Metrics{}
	var err error
	if metrics.consumed, err = meter.Int64Counter("metocean.messages.consumed",
		metric.WithDescription("Advisory topic records consumed, by outcome")); err != nil {
		return nil, err
	}
	if metrics.rejected, err = meter.Int64Counter("metocean.envelope.rejected",
		metric.WithDescription("Envelopes rejected by signature verification or contract parsing, by reason code")); err != nil {
		return nil, err
	}
	if metrics.dlq, err = meter.Int64Counter("metocean.dlq.published",
		metric.WithDescription("Records dead-lettered, by reason code")); err != nil {
		return nil, err
	}
	if metrics.dispatched, err = meter.Int64Counter("metocean.advisory.dispatched",
		metric.WithDescription("Verified advisories dispatched to route workflows, by message type")); err != nil {
		return nil, err
	}
	if metrics.skipped, err = meter.Int64Counter("metocean.advisory.skipped",
		metric.WithDescription("Verified advisories not dispatched, by reason")); err != nil {
		return nil, err
	}
	return metrics, nil
}

// Consumer reads the advisory topic, verifies every envelope per the fleet
// signature scheme (fail closed, terminal rejection), dead-letters
// rejections with the reason code and dispatches verified advisories. It
// never processes an unverified or rejected envelope.
type Consumer struct {
	source     MessageSource
	dlq        Sink
	dispatcher Dispatcher
	directory  *provenance.Directory
	topic      string
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	metrics    *Metrics
	logger     *slog.Logger
}

// NewConsumer fails closed on any missing dependency: verification and
// dead-lettering are mandatory, never best-effort.
func NewConsumer(source MessageSource, dlq Sink, dispatcher Dispatcher, directory *provenance.Directory, topic string, tracer trace.Tracer, metrics *Metrics, logger *slog.Logger) (*Consumer, error) {
	if source == nil || dlq == nil || dispatcher == nil {
		return nil, errors.New("message source, dead-letter sink and dispatcher are required")
	}
	if directory == nil {
		return nil, errors.New("provenance key directory is required (fail-closed)")
	}
	if topic != AdvisoryTopic {
		return nil, fmt.Errorf("consumer topic %q is not the approved advisory topic %q", topic, AdvisoryTopic)
	}
	if tracer == nil {
		return nil, errors.New("tracer is required")
	}
	if metrics == nil {
		return nil, errors.New("metrics are required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &Consumer{
		source:     source,
		dlq:        dlq,
		dispatcher: dispatcher,
		directory:  directory,
		topic:      topic,
		tracer:     tracer,
		propagator: propagation.TraceContext{},
		metrics:    metrics,
		logger:     logger,
	}, nil
}

// Run consumes until ctx is cancelled. A record that fails dead-lettering or
// dispatch is not committed; it is logged, metered and retried on the next
// rebalance or restart (at-least-once), never silently dropped.
func (consumer *Consumer) Run(ctx context.Context) error {
	for {
		message, err := consumer.source.Fetch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			consumer.logger.Error("advisory fetch failed; retrying", "error", err.Error())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if err := consumer.process(ctx, message); err != nil {
			consumer.logger.Error("advisory record not committed; will be redelivered",
				"error", err.Error(), "partition", message.Partition, "offset", message.Offset)
		}
	}
}

// process handles one record: verify -> parse -> dispatch -> commit, with a
// consumer span parented to the producer traceparent header when present.
func (consumer *Consumer) process(ctx context.Context, message Message) error {
	extracted := consumer.propagator.Extract(ctx, headerCarrier(message.Headers))
	spanContext, span := consumer.tracer.Start(extracted, "metocean.consume",
		trace.WithSpanKind(trace.SpanKindConsumer),
		trace.WithAttributes(
			attribute.String("messaging.system", "kafka"),
			attribute.String("messaging.destination.name", message.Topic),
			attribute.Int("messaging.kafka.partition", message.Partition),
			attribute.Int64("messaging.kafka.offset", message.Offset),
		))
	defer span.End()

	fail := func(reason string, cause error) error {
		span.SetStatus(codes.Error, reason)
		consumer.metrics.rejected.Add(spanContext, 1, metric.WithAttributes(attribute.String("reason", reason)))
		consumer.metrics.consumed.Add(spanContext, 1, metric.WithAttributes(attribute.String("outcome", "rejected")))
		if dlqErr := consumer.deadLetter(spanContext, message, reason); dlqErr != nil {
			consumer.logger.Error("dead-letter publish failed", "error", dlqErr.Error(), "reason", reason)
			return fmt.Errorf("dead-letter rejected record: %w", dlqErr)
		}
		consumer.logger.Warn("advisory record rejected and dead-lettered",
			"reason", reason, "error", cause.Error(), "partition", message.Partition, "offset", message.Offset)
		return consumer.commit(spanContext, message)
	}

	if err := consumer.directory.VerifyEnvelopeStrict(message.Value); err != nil {
		reason := provenance.RejectionReason(err)
		if reason == "" {
			reason = ReasonMalformedAdvisory
		}
		return fail(reason, err)
	}
	advisory, err := ParseAdvisory(message.Value)
	if err != nil {
		return fail(ReasonMalformedAdvisory, err)
	}
	if advisory.Producer != AdvisoryProducer {
		// Suspicious per the signature doc, but the key directory is the
		// sole source of truth for key resolution: meter and continue.
		consumer.logger.Warn("advisory producer does not match the expected producer",
			"producer", advisory.Producer, "expected", AdvisoryProducer, "event_id", advisory.EventID)
		consumer.metrics.skipped.Add(spanContext, 1, metric.WithAttributes(attribute.String("reason", "producer-mismatch-observed")))
	}
	span.SetAttributes(
		attribute.String("metocean.advisory_id", advisory.AdvisoryID),
		attribute.String("metocean.msg_type", advisory.MsgType),
		attribute.String("metocean.severity", advisory.Severity),
		attribute.String("metocean.zone_id", advisory.ZoneID),
	)
	if err := consumer.dispatcher.Dispatch(spanContext, advisory); err != nil {
		var unmapped *UnmappedZoneError
		if errors.As(err, &unmapped) {
			return fail(ReasonUnmappedZone, err)
		}
		// Transient dispatch failure: do not commit; redelivery retries.
		span.SetStatus(codes.Error, "dispatch failed")
		return fmt.Errorf("dispatch advisory %s: %w", advisory.AdvisoryID, err)
	}
	consumer.metrics.dispatched.Add(spanContext, 1, metric.WithAttributes(attribute.String("msg_type", advisory.MsgType)))
	consumer.metrics.consumed.Add(spanContext, 1, metric.WithAttributes(attribute.String("outcome", "processed")))
	return consumer.commit(spanContext, message)
}

// deadLetter publishes the raw record to the dead-letter topic with the
// rejection reason and source coordinates; the original traceparent stays on
// the record for downstream diagnosis.
func (consumer *Consumer) deadLetter(ctx context.Context, message Message, reason string) error {
	headers := make([]Header, 0, len(message.Headers)+5)
	headers = append(headers, message.Headers...)
	headers = append(headers,
		Header{Key: HeaderDLQReason, Value: []byte(reason)},
		Header{Key: HeaderDLQSourceTopic, Value: []byte(message.Topic)},
		Header{Key: HeaderDLQPartition, Value: []byte(fmt.Sprintf("%d", message.Partition))},
		Header{Key: HeaderDLQOffset, Value: []byte(fmt.Sprintf("%d", message.Offset))},
		Header{Key: HeaderDLQOriginalKey, Value: message.Key},
	)
	key := message.Key
	if len(key) == 0 {
		key = []byte(fmt.Sprintf("%s-%d-%d", message.Topic, message.Partition, message.Offset))
	}
	if err := consumer.dlq.Publish(ctx, key, message.Value, headers); err != nil {
		return err
	}
	consumer.metrics.dlq.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	return nil
}

func (consumer *Consumer) commit(ctx context.Context, message Message) error {
	if err := consumer.source.Commit(ctx, message); err != nil {
		return fmt.Errorf("commit offset: %w", err)
	}
	return nil
}
