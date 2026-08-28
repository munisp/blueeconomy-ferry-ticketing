package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

// testSigner returns a throwaway provenance signer for envelope tests.
func testSigner(t *testing.T) *provenance.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := provenance.NewSigner(SigningKeyID, private)
	require.NoError(t, err)
	return signer
}

// requireValidSignature verifies the envelope provenance signature against
// the signer's public key, binding it to the exact signed document.
func requireValidSignature(t *testing.T, signer *provenance.Signer, envelope Envelope) {
	t.Helper()
	require.NotEmpty(t, envelope.Provenance.Signature)
	directory, err := provenance.ParseDirectory([]byte(fmt.Sprintf(`{%q:%q}`, signer.KeyID(), signer.PublicKey())))
	require.NoError(t, err)
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	require.NoError(t, directory.VerifyEnvelope(raw), "provenance signature must verify over the sealed envelope")
}

func ticketingEvent() Event {
	return Event{
		EventID:   "event-1",
		Topic:     "ferries.ticketing.v1",
		SubjectID: "ticket-1",
		EventType: "ferry.ticket.issued",
		Payload: json.RawMessage(`{
			"ticket_id": "ticket-1",
			"principal_id": "keycloak-sub-1",
			"principal_role": "passenger",
			"ledger_transfer_id": "abc123",
			"state": "ISSUED"
		}`),
		CorrelationID: "corr-1",
		CreatedAt:     time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
	}
}

func TestBuildEnvelopeMatchesPlatformContract(t *testing.T) {
	signer := testSigner(t)
	envelope, err := BuildEnvelope(ticketingEvent(), signer)
	require.NoError(t, err)
	require.Equal(t, "1.0", envelope.EnvelopeVersion)
	require.Equal(t, "event-1", envelope.EventID)
	require.Equal(t, "ferries.ticketing.ticket.v1", envelope.EventType)
	require.Equal(t, "2026-09-01T08:00:00Z", envelope.OccurredAt)
	require.Equal(t, "ferry-ticketing", envelope.Producer)
	require.Equal(t, "corr-1", envelope.CorrelationID)
	require.Equal(t, "INTERNAL", envelope.Classification)
	require.Equal(t, "Bundle", envelope.FHIR.ResourceType)
	require.Equal(t, "message", envelope.FHIR.Type)
	require.Len(t, envelope.FHIR.Entry, 1)
	require.Equal(t, "keycloak-sub-1", envelope.Provenance.PrincipalID)
	require.Equal(t, "passenger", envelope.Provenance.PrincipalRole)
	require.Equal(t, "abc123", envelope.Provenance.LedgerCommitHash)
	requireValidSignature(t, signer, envelope)

	resource, ok := envelope.FHIR.Entry[0].Resource.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "ferry.ticket.issued", resource["internalEventType"])
	require.Equal(t, "ticket-1", resource["subjectId"])
}

func TestBuildEnvelopeFailsClosed(t *testing.T) {
	missing := ticketingEvent()
	missing.EventID = ""
	_, err := BuildEnvelope(missing, testSigner(t))
	require.Error(t, err)

	unknownType := ticketingEvent()
	unknownType.EventType = "ferry.ticket.teleported"
	_, err = BuildEnvelope(unknownType, testSigner(t))
	require.Error(t, err)

	unknownTopic := ticketingEvent()
	unknownTopic.Topic = "ferries.debug.v1"
	_, err = BuildEnvelope(unknownTopic, testSigner(t))
	require.Error(t, err)

	badPayload := ticketingEvent()
	badPayload.Payload = json.RawMessage(`[1,2]`)
	_, err = BuildEnvelope(badPayload, testSigner(t))
	require.Error(t, err)
}

// TestBuildEnvelopeFraudTelemetry pins the security-operations contract:
// fraud events map to their dedicated envelope types on the ticketing topic
// with the CONFIDENTIAL classification.
func TestBuildEnvelopeFraudTelemetry(t *testing.T) {
	failed := ticketingEvent()
	failed.EventType = "ferry.ticket.verification_failed"
	failed.Payload = json.RawMessage(`{"ticket_id": "ticket-1", "principal_id": "gate-1", "artifact_kid": "ab12", "reason": "invalid_signature"}`)
	envelope, err := BuildEnvelope(failed, testSigner(t))
	require.NoError(t, err)
	require.Equal(t, "ferries.ticketing.ticket_verification_failed.v1", envelope.EventType)
	require.Equal(t, "CONFIDENTIAL", envelope.Classification)
	require.Equal(t, "gate-1", envelope.Provenance.PrincipalID)

	duplicate := ticketingEvent()
	duplicate.EventType = "ferry.ticket.duplicate_presentation"
	duplicate.Payload = json.RawMessage(`{"ticket_id": "ticket-1", "principal_id": "gate-2", "first_boarded_by": "gate-1"}`)
	envelope, err = BuildEnvelope(duplicate, testSigner(t))
	require.NoError(t, err)
	require.Equal(t, "ferries.ticketing.ticket_duplicate_presentation.v1", envelope.EventType)
	require.Equal(t, "CONFIDENTIAL", envelope.Classification)
}

type fakeSource struct {
	events    []Event
	published []string
	markErr   error
}

func (source *fakeSource) Unpublished(_ context.Context, limit int) ([]Event, error) {
	if limit > len(source.events) {
		return source.events, nil
	}
	return source.events[:limit], nil
}

func (source *fakeSource) MarkPublished(_ context.Context, event Event) error {
	if source.markErr != nil {
		return source.markErr
	}
	source.published = append(source.published, event.EventID)
	return nil
}

type fakeProducer struct {
	keys   []string
	values [][]byte
	err    error
}

func (producer *fakeProducer) Publish(_ context.Context, key, value []byte) error {
	if producer.err != nil {
		return producer.err
	}
	producer.keys = append(producer.keys, string(key))
	producer.values = append(producer.values, value)
	return nil
}

func TestDrainPublishesWithIdempotentKeys(t *testing.T) {
	second := ticketingEvent()
	second.EventID = "event-2"
	second.EventType = "ferry.manifest.exported"
	second.Topic = "ferries.manifest.v1"
	source := &fakeSource{events: []Event{ticketingEvent(), second}}
	producer := &fakeProducer{}
	ticketingProducer := &fakeProducer{}
	manifestProducer := producer
	router := MapRouter{
		"ferries.ticketing.v1": ticketingProducer,
		"ferries.manifest.v1":  manifestProducer,
	}
	published, err := Drain(context.Background(), source, router, testSigner(t), 10)
	require.NoError(t, err)
	require.Equal(t, 2, published)
	require.Equal(t, []string{"event-1", "event-2"}, source.published)
	require.Equal(t, []string{"event-1"}, ticketingProducer.keys, "idempotent key is the event id")
	require.Equal(t, []string{"event-2"}, producer.keys)
	var envelope Envelope
	require.NoError(t, json.Unmarshal(ticketingProducer.values[0], &envelope))
	require.Equal(t, "ferry-ticketing", envelope.Producer)
}

func TestDrainAbortsFailClosedOnPublishFailure(t *testing.T) {
	source := &fakeSource{events: []Event{ticketingEvent()}}
	producer := &fakeProducer{err: errors.New("kafka unreachable")}
	router := MapRouter{"ferries.ticketing.v1": producer}
	published, err := Drain(context.Background(), source, router, testSigner(t), 10)
	require.Error(t, err)
	require.Equal(t, 0, published)
	require.Empty(t, source.published, "never mark published before the broker accepts")
}

func TestDrainFailsClosedOnUnknownTopicRoute(t *testing.T) {
	source := &fakeSource{events: []Event{ticketingEvent()}}
	published, err := Drain(context.Background(), source, MapRouter{}, testSigner(t), 10)
	require.Error(t, err)
	require.Equal(t, 0, published)
}

func TestDrainValidatesDependencies(t *testing.T) {
	_, err := Drain(context.Background(), nil, MapRouter{}, testSigner(t), 10)
	require.Error(t, err)
	_, err = Drain(context.Background(), &fakeSource{}, nil, testSigner(t), 10)
	require.Error(t, err)
	_, err = Drain(context.Background(), &fakeSource{}, MapRouter{}, testSigner(t), 0)
	require.Error(t, err)
}

func TestNewKafkaProducerFailsClosed(t *testing.T) {
	_, err := NewKafkaProducer("", "ferries.ticketing.v1")
	require.Error(t, err)
	_, err = NewKafkaProducer("kafka:9092", "")
	require.Error(t, err)
	_, err = NewKafkaProducer("kafka:9092", "unapproved.topic")
	require.Error(t, err)
	producer, err := NewKafkaProducer("kafka:9092", "ferries.manifest.v1")
	require.NoError(t, err)
	require.NoError(t, producer.Close())
}
