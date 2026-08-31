// Package outbox drains the ferry transactional outbox to Kafka with the
// platform FHIR-aligned envelope, at-least-once delivery and idempotent keys.
package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

// SigningKeyID is the provenance key id this producer signs envelopes with;
// consumers resolve the matching public key from the fleet key directory.
const SigningKeyID = "ferry-ticketing-1"

const (
	// EnvelopeVersion is the binding platform envelope version.
	EnvelopeVersion = "1.0"
	// ProducerName identifies this service in every envelope.
	ProducerName = "ferry-ticketing"
	// ClassificationInternal is the default envelope handling classification.
	ClassificationInternal = "INTERNAL"
	// ClassificationConfidential marks fraud-telemetry envelopes restricted
	// to the security-operations boundary.
	ClassificationConfidential = "CONFIDENTIAL"
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
	"ferries.ticketing.v1":     {},
	"ferries.manifest.v1":      {},
	"ferries.notifications.v1": {},
	"ferries.fare.v1":          {},

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
	// Passenger notifications from the met-ocean bridge (advisory-driven
	// departure suspensions and resumptions).
	"ferry.trip.departure_suspended": "ferries.notifications.departure_suspended.v1",
	"ferry.trip.departure_resumed":   "ferries.notifications.departure_resumed.v1",
	// Fraud telemetry consumed by the security-operations engine.
	"ferry.ticket.verification_failed":    "ferries.ticketing.ticket_verification_failed.v1",
	"ferry.ticket.duplicate_presentation": "ferries.ticketing.ticket_duplicate_presentation.v1",
}

// confidentialEventTypes are restricted to the security-operations boundary
// (envelope classification CONFIDENTIAL); everything else is INTERNAL.
var confidentialEventTypes = map[string]struct{}{
	"ferry.ticket.verification_failed":    {},
	"ferry.ticket.duplicate_presentation": {},
}

// BuildEnvelope maps one outbox event to the platform envelope and seals it
// with the fleet provenance signature (JWS EdDSA over the JCS-canonicalized
// envelope excluding the signature field). It fails closed on a missing
// signer, unknown event types, unknown topics and malformed payloads.
func BuildEnvelope(event Event, signer *provenance.Signer) (Envelope, error) {
	if signer == nil {
		return Envelope{}, errors.New("provenance signer is required")
	}
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
	correlationID := event.CorrelationID
	if correlationID == "" {
		correlationID = event.EventID
	}
	classification := ClassificationInternal
	if _, confidential := confidentialEventTypes[event.EventType]; confidential {
		classification = ClassificationConfidential
	}
	envelope := Envelope{
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
			LedgerCommitHash: stringField(resource, "ledger_transfer_id", "ledger_post_id", "manifest_digest_sha256"),
		},
		Classification: classification,
	}
	signature, err := signer.SignEnvelope(envelope)
	if err != nil {
		return Envelope{}, fmt.Errorf("sign envelope provenance for %s: %w", event.EventID, err)
	}
	envelope.Provenance.Signature = signature
	return envelope, nil
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
