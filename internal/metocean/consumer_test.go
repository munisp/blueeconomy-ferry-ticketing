package metocean

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

const consumerTestKid = "blueeconomy-waterway-safety-0"

func consumerTestSigner(t *testing.T) *provenance.Signer {
	t.Helper()
	signer, err := provenance.NewSigner(consumerTestKid, testSeed())
	require.NoError(t, err)
	return signer
}

func consumerTestDirectory(t *testing.T, signer *provenance.Signer) *provenance.Directory {
	t.Helper()
	raw, err := json.Marshal(map[string]string{signer.KeyID(): signer.PublicKey()})
	require.NoError(t, err)
	directory, err := provenance.ParseDirectory(raw)
	require.NoError(t, err)
	return directory
}

// signedAdvisoryEnvelope builds a signed advisory envelope for consumer tests.
func signedAdvisoryEnvelope(t *testing.T, signer *provenance.Signer, advisoryID, msgType, severity, zoneID string) []byte {
	t.Helper()
	resource := map[string]any{
		"@type":                ResourceType,
		"advisoryId":           advisoryID,
		"sender":               AdvisoryProducer,
		"msgType":              msgType,
		"category":             "Met",
		"phenomenonCode":       "HIGH_SIGNIFICANT_WAVE_HEIGHT",
		"urgency":              "Expected",
		"severity":             severity,
		"certainty":            "Likely",
		"zoneId":               zoneID,
		"effectiveFrom":        "2026-08-29T18:00:00Z",
		"onset":                "2026-08-29T21:00:00Z",
		"effectiveUntil":       "2026-08-30T06:00:00Z",
		"bulletinReference":    "sha256:" + strings.Repeat("ab", 32),
		"referencesAdvisoryId": "",
		"source":               "FEED",
		"feedKind":             "OPEN_METEO_MARINE",
		"attributionText":      "Weather data by Open-Meteo.com",
		"status":               "ACTIVE",
		"policyDigestSha256":   "sha256:" + strings.Repeat("cd", 32),
		"issuedAt":             "2026-08-29T14:00:00Z",
	}
	if msgType == MsgTypeCancel {
		resource["status"] = "CANCELLED"
		resource["referencesAdvisoryId"] = "moa-referenced"
	}
	envelope := map[string]any{
		"envelopeVersion": "1.0",
		"eventId":         "evt-" + advisoryID,
		"eventType":       AdvisoryEventType,
		"occurredAt":      "2026-08-29T14:00:00Z",
		"producer":        AdvisoryProducer,
		"correlationId":   "corr-" + advisoryID,
		"classification":  "INTERNAL",
		"fhir": map[string]any{
			"resourceType": "Bundle",
			"type":         "message",
			"bundleId":     "bdl-" + advisoryID,
			"entry":        []any{map[string]any{"fullUrl": "urn:uuid:x", "resource": resource}},
		},
		"provenance": map[string]any{
			"principalId":      "principal-1",
			"principalRole":    "metocean-producer",
			"ledgerCommitHash": "",
		},
	}
	signature, err := signer.SignEnvelope(envelope)
	require.NoError(t, err)
	envelope["provenance"].(map[string]any)["signature"] = signature
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	return raw
}

// fakeSource feeds a fixed list of messages.
type fakeSource struct {
	mu        sync.Mutex
	messages  []Message
	committed []Message
}

func (source *fakeSource) Fetch(ctx context.Context) (Message, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.messages) == 0 {
		<-ctx.Done()
		return Message{}, ctx.Err()
	}
	message := source.messages[0]
	source.messages = source.messages[1:]
	return message, nil
}

func (source *fakeSource) Commit(_ context.Context, message Message) error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.committed = append(source.committed, message)
	return nil
}

func (source *fakeSource) Close() error { return nil }

type deadLetter struct {
	key, value []byte
	headers    []Header
}

type fakeSink struct {
	mu        sync.Mutex
	published []deadLetter
	err       error
}

func (sink *fakeSink) Publish(_ context.Context, key, value []byte, headers []Header) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	sink.published = append(sink.published, deadLetter{key: key, value: value, headers: headers})
	return nil
}

func (sink *fakeSink) Close() error { return nil }

type fakeDispatcher struct {
	mu         sync.Mutex
	dispatched []Advisory
	err        error
}

func (dispatcher *fakeDispatcher) Dispatch(_ context.Context, advisory Advisory) error {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.err != nil {
		return dispatcher.err
	}
	dispatcher.dispatched = append(dispatcher.dispatched, advisory)
	return nil
}

func dlqReason(t *testing.T, letter deadLetter) string {
	t.Helper()
	for _, header := range letter.headers {
		if header.Key == HeaderDLQReason {
			return string(header.Value)
		}
	}
	t.Fatal("dead letter carries no reason header")
	return ""
}

type consumerFixture struct {
	consumer   *Consumer
	source     *fakeSource
	sink       *fakeSink
	dispatcher *fakeDispatcher
	cancel     context.CancelFunc
	done       chan error
}

func newConsumerFixture(t *testing.T, tracer trace.Tracer) *consumerFixture {
	t.Helper()
	signer := consumerTestSigner(t)
	directory := consumerTestDirectory(t, signer)
	metrics, err := NewMetrics(noopMeter())
	require.NoError(t, err)
	fixture := &consumerFixture{
		source:     &fakeSource{},
		sink:       &fakeSink{},
		dispatcher: &fakeDispatcher{},
		done:       make(chan error, 1),
	}
	consumer, err := NewConsumer(fixture.source, fixture.sink, fixture.dispatcher, directory,
		AdvisoryTopic, tracer, metrics, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	require.NoError(t, err)
	fixture.consumer = consumer
	return fixture
}

func (fixture *consumerFixture) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	go func() { fixture.done <- fixture.consumer.Run(ctx) }()
}

func (fixture *consumerFixture) stop(t *testing.T) {
	t.Helper()
	fixture.cancel()
	require.NoError(t, <-fixture.done)
}

func signedMessage(t *testing.T, signer *provenance.Signer, advisoryID, msgType, severity, zoneID string) Message {
	t.Helper()
	return Message{
		Key:   []byte(advisoryID),
		Value: signedAdvisoryEnvelope(t, signer, advisoryID, msgType, severity, zoneID),
		Topic: AdvisoryTopic,
	}
}

func TestConsumerDispatchesVerifiedAdvisory(t *testing.T) {
	fixture := newConsumerFixture(t, noopTracer())
	signer := consumerTestSigner(t)
	fixture.source.messages = append(fixture.source.messages,
		signedMessage(t, signer, "moa-1", MsgTypeAlert, "Severe", "hz-lagos-approach"))
	fixture.run(t)
	require.Eventually(t, func() bool {
		fixture.dispatcher.mu.Lock()
		defer fixture.dispatcher.mu.Unlock()
		return len(fixture.dispatcher.dispatched) == 1
	}, waitTimeout, pollInterval)
	fixture.stop(t)
	fixture.dispatcher.mu.Lock()
	require.Equal(t, "moa-1", fixture.dispatcher.dispatched[0].AdvisoryID)
	fixture.dispatcher.mu.Unlock()
	require.Empty(t, fixture.sink.published)
	require.Len(t, fixture.source.committed, 1)
}

func TestConsumerDeadLettersRejectedEnvelopes(t *testing.T) {
	signer := consumerTestSigner(t)
	valid := signedMessage(t, signer, "moa-ok", MsgTypeAlert, "Severe", "hz-lagos-approach")

	tampered := signedMessage(t, signer, "moa-tampered", MsgTypeAlert, "Severe", "hz-lagos-approach")
	tampered.Value = []byte(strings.Replace(string(tampered.Value), `"Severe"`, `"Extreme"`, 1))

	unknownKid := signedMessage(t, signer, "moa-unknown", MsgTypeAlert, "Severe", "hz-lagos-approach")
	other, err := provenance.NewSigner("other-producer-0", testSeed())
	require.NoError(t, err)
	unknownKid.Value = signedAdvisoryEnvelope(t, other, "moa-unknown", MsgTypeAlert, "Severe", "hz-lagos-approach")

	notJSON := Message{Key: []byte("bad"), Value: []byte("{not json"), Topic: AdvisoryTopic}

	cases := map[string]struct {
		message Message
		reason  string
	}{
		"payload mismatch": {tampered, provenance.ReasonPayloadMismatch},
		"unknown kid":      {unknownKid, provenance.ReasonUnknownKid},
		"malformed jws":    {notJSON, provenance.ReasonMalformedJWS},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newConsumerFixture(t, noopTracer())
			fixture.source.messages = append(fixture.source.messages, testCase.message, valid)
			fixture.run(t)
			require.Eventually(t, func() bool {
				fixture.sink.mu.Lock()
				defer fixture.sink.mu.Unlock()
				return len(fixture.sink.published) == 1
			}, waitTimeout, pollInterval)
			fixture.stop(t)
			require.Equal(t, testCase.reason, dlqReason(t, fixture.sink.published[0]))
			require.Equal(t, testCase.message.Value, fixture.sink.published[0].value)
			// The rejected record is committed (terminal rejection), the
			// valid one is processed, and the dispatcher only saw the valid.
			require.Len(t, fixture.source.committed, 2)
			fixture.dispatcher.mu.Lock()
			require.Len(t, fixture.dispatcher.dispatched, 1)
			require.Equal(t, "moa-ok", fixture.dispatcher.dispatched[0].AdvisoryID)
			fixture.dispatcher.mu.Unlock()
		})
	}
}

func TestConsumerDeadLettersUnmappedZone(t *testing.T) {
	fixture := newConsumerFixture(t, noopTracer())
	signer := consumerTestSigner(t)
	fixture.dispatcher.err = &UnmappedZoneError{ZoneID: "hz-nowhere"}
	fixture.source.messages = append(fixture.source.messages,
		signedMessage(t, signer, "moa-zone", MsgTypeAlert, "Severe", "hz-nowhere"))
	fixture.run(t)
	require.Eventually(t, func() bool {
		fixture.sink.mu.Lock()
		defer fixture.sink.mu.Unlock()
		return len(fixture.sink.published) == 1
	}, waitTimeout, pollInterval)
	fixture.stop(t)
	require.Equal(t, ReasonUnmappedZone, dlqReason(t, fixture.sink.published[0]))
	require.Len(t, fixture.source.committed, 1)
}

func TestConsumerDoesNotCommitOnTransientDispatchFailure(t *testing.T) {
	fixture := newConsumerFixture(t, noopTracer())
	signer := consumerTestSigner(t)
	fixture.dispatcher.err = errors.New("temporal unavailable")
	fixture.source.messages = append(fixture.source.messages,
		signedMessage(t, signer, "moa-retry", MsgTypeAlert, "Severe", "hz-lagos-approach"))
	fixture.run(t)
	require.Eventually(t, func() bool {
		fixture.dispatcher.mu.Lock()
		defer fixture.dispatcher.mu.Unlock()
		return len(fixture.dispatcher.dispatched) == 0
	}, waitTimeout, pollInterval)
	// Give the consumer a moment; it must neither commit nor dead-letter.
	fixture.stop(t)
	require.Empty(t, fixture.source.committed)
	require.Empty(t, fixture.sink.published)
}

func TestConsumerDoesNotCommitWhenDeadLetterFails(t *testing.T) {
	fixture := newConsumerFixture(t, noopTracer())
	fixture.sink.err = errors.New("kafka down")
	fixture.source.messages = append(fixture.source.messages,
		Message{Key: []byte("bad"), Value: []byte("{not json"), Topic: AdvisoryTopic})
	fixture.run(t)
	fixture.stop(t)
	require.Empty(t, fixture.source.committed)
}

func TestConsumerExtractsTraceparent(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	tracer := provider.Tracer("metocean-test")
	fixture := newConsumerFixture(t, tracer)
	signer := consumerTestSigner(t)
	message := signedMessage(t, signer, "moa-trace", MsgTypeAlert, "Severe", "hz-lagos-approach")
	message.Headers = []Header{{Key: "traceparent", Value: []byte("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")}}
	fixture.source.messages = append(fixture.source.messages, message)
	fixture.run(t)
	require.Eventually(t, func() bool {
		return len(recorder.Ended()) > 0
	}, waitTimeout, pollInterval)
	fixture.stop(t)
	spans := recorder.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "metocean.consume", spans[0].Name())
	require.Equal(t, trace.SpanKindConsumer, spans[0].SpanKind())
	// The consumer span is parented to the remote trace context.
	require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", spans[0].Parent().TraceID().String())
	require.Equal(t, "00f067aa0ba902b7", spans[0].Parent().SpanID().String())
}

func TestNewConsumerFailClosed(t *testing.T) {
	signer := consumerTestSigner(t)
	directory := consumerTestDirectory(t, signer)
	metrics, err := NewMetrics(noopMeter())
	require.NoError(t, err)
	source := &fakeSource{}
	sink := &fakeSink{}
	dispatcher := &fakeDispatcher{}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	_, err = NewConsumer(nil, sink, dispatcher, directory, AdvisoryTopic, noopTracer(), metrics, logger)
	require.Error(t, err)
	_, err = NewConsumer(source, nil, dispatcher, directory, AdvisoryTopic, noopTracer(), metrics, logger)
	require.Error(t, err)
	_, err = NewConsumer(source, sink, dispatcher, nil, AdvisoryTopic, noopTracer(), metrics, logger)
	require.Error(t, err)
	_, err = NewConsumer(source, sink, dispatcher, directory, "other.topic.v1", noopTracer(), metrics, logger)
	require.Error(t, err)
}
