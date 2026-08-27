// Package outbox drains the ferry transactional outbox to Kafka with the
// platform FHIR-aligned envelope, at-least-once delivery and idempotent keys.
package outbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// EnvelopeVersion is the binding platform envelope version.
	EnvelopeVersion = "1.0"
	// ProducerName identifies this service in every envelope.
	ProducerName = "ferry-ticketing"
	// ClassificationInternal is the envelope handling classification.
	ClassificationInternal = "INTERNAL"
)

// Event is one unpublished outbox row.
type Event struct {
	EventID       string
	Topic         string
	SubjectID     string
	EventType     string
	Payload       json.RawMessage
	CorrelationID string
	CreatedAt     time.Time
}

// Envelope is the binding platform message envelope
// (blueeconomy.contracts.v1.EventEnvelope, JSON rendering).
type Envelope struct {
	EnvelopeVersion string     `json:"envelopeVersion"`
	EventID         string     `json:"eventId"`
	EventType       string     `json:"eventType"`
	OccurredAt      string     `json:"occurredAt"`
	Producer        string     `json:"producer"`
	CorrelationID   string     `json:"correlationId"`
	FHIR            FHIRBundle `json:"fhir"`
	Provenance      Provenance `json:"provenance"`
	Classification  string     `json:"classification"`
}

// FHIRBundle is the FHIR-aligned message wrapper.
type FHIRBundle struct {
	ResourceType string      `json:"resourceType"`
	Type         string      `json:"type"`
	Entry        []FHIREntry `json:"entry"`
}

// FHIREntry wraps one domain resource.
type FHIREntry struct {
	Resource any `json:"resource"`
}

// Provenance binds the envelope to the deciding principal and ledger commit.
type Provenance struct {
	PrincipalID      string `json:"principalId"`
	PrincipalRole    string `json:"principalRole"`
	Signature        string `json:"signature"`
	LedgerCommitHash string `json:"ledgerCommitHash"`
}

// topics is the topic allowlist; anything else fails closed.
var topics = map[string]struct{}{
	"ferries.ticketing.v1": {},
	"ferries.manifest.v1":  {},
}

// envelopeEventTypes maps internal outbox event types to envelope event types.
// Unknown types fail closed.
var envelopeEventTypes = map[string]string{
	"ferry.ticket.reserved":         "ferries.ticketing.ticket.v1",
	"ferry.ticket.paid":             "ferries.ticketing.ticket.v1",
	"ferry.ticket.issued":           "ferries.ticketing.ticket.v1",
	"ferry.ticket.refunded":         "ferries.ticketing.ticket.v1",
	"ferry.ticket.expired":          "ferries.ticketing.ticket.v1",
	"ferry.ticket.voided":           "ferries.ticketing.ticket.v1",
	"ferry.agent.cash_in_recorded":  "ferries.ticketing.cash_in.v1",
	"ferry.manifest.exported":       "ferries.manifest.submitted.v1",
	"ferry.manifest.incomplete":     "ferries.manifest.incomplete.v1",
	"ferry.adverse_weather.alerted": "ferries.manifest.adverse_weather.v1",
}

// BuildEnvelope maps one outbox event to the platform envelope. It fails
// closed on unknown event types, unknown topics and malformed payloads.
func BuildEnvelope(event Event) (Envelope, error) {
	if event.EventID == "" || event.SubjectID == "" || event.EventType == "" || len(event.Payload) == 0 {
		return Envelope{}, errors.New("outbox event identifiers and payload are required")
	}
	if _, ok := topics[event.Topic]; !ok {
		return Envelope{}, fmt.Errorf("outbox topic %q is not approved", event.Topic)
	}
	eventType, ok := envelopeEventTypes[event.EventType]
	if !ok {
		return Envelope{}, fmt.Errorf("outbox event type %q has no envelope mapping", event.EventType)
	}
	var resource map[string]any
	if err := json.Unmarshal(event.Payload, &resource); err != nil {
		return Envelope{}, fmt.Errorf("decode outbox payload: %w", err)
	}
	if resource == nil {
		return Envelope{}, errors.New("outbox payload is not a JSON object")
	}
	resource["internalEventType"] = event.EventType
	resource["subjectId"] = event.SubjectID
	digest := sha256.Sum256(event.Payload)
	correlationID := event.CorrelationID
	if correlationID == "" {
		correlationID = event.EventID
	}
	return Envelope{
		EnvelopeVersion: EnvelopeVersion,
		EventID:         event.EventID,
		EventType:       eventType,
		OccurredAt:      event.CreatedAt.UTC().Format(time.RFC3339),
		Producer:        ProducerName,
		CorrelationID:   correlationID,
		FHIR: FHIRBundle{
			ResourceType: "Bundle",
			Type:         "message",
			Entry:        []FHIREntry{{Resource: resource}},
		},
		Provenance: Provenance{
			PrincipalID:      stringField(resource, "principal_id", "exported_by_principal"),
			PrincipalRole:    stringField(resource, "principal_role", "state"),
			Signature:        hex.EncodeToString(digest[:]),
			LedgerCommitHash: stringField(resource, "ledger_transfer_id", "ledger_post_id", "manifest_digest_sha256"),
		},
		Classification: ClassificationInternal,
	}, nil
}

func stringField(resource map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := resource[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

// IdempotentKey returns the stable Kafka message key for at-least-once
// republish safety.
func IdempotentKey(event Event) string { return event.EventID }
