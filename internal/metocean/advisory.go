// Package metocean implements the ferry met-ocean bridge: a Kafka consumer
// for waterways.met_ocean.advisories.v1 that verifies every envelope per the
// fleet provenance-signature scheme (fail closed, no unsigned admission),
// dead-letters rejections, and drives per-route Temporal workflows that
// suspend and resume affected scheduled departures.
package metocean

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// AdvisoryTopic is the binding Kafka topic for met-ocean advisories.
	AdvisoryTopic = "waterways.met_ocean.advisories.v1"
	// AdvisoryEventType is the only envelope event type this bridge consumes.
	AdvisoryEventType = "waterways.met_ocean.advisory.v1"
	// AdvisoryProducer is the expected envelope producer field. A mismatch
	// with the resolved key id prefix is suspicious and metered; the key
	// directory remains the sole source of truth for key resolution.
	AdvisoryProducer = "blueeconomy-waterway-safety"
	// EnvelopeVersion is the only accepted envelope version.
	EnvelopeVersion = "1.0"
	// ResourceType is the FHIR Bundle entry resource type URL of the
	// advisory primary resource.
	ResourceType = "type.googleapis.com/blueeconomy.contracts.v1.MetoceanAdvisoryIssued"
)

// CAP 1.2 message types governing the advisory lifecycle. Cancel is
// explicit: an active advisory is terminated only by a Cancel advisory
// carrying ReferencesAdvisoryID, never by silent absence.
const (
	MsgTypeAlert  = "Alert"
	MsgTypeUpdate = "Update"
	MsgTypeCancel = "Cancel"
)

// Advisory status values.
const (
	StatusActive    = "ACTIVE"
	StatusCancelled = "CANCELLED"
)

// Advisory source channels.
const (
	SourceFeed             = "FEED"
	SourceOperatorOverride = "OPERATOR_OVERRIDE"
)

// CAP 1.2 code tables (rendered without enum prefixes).
var (
	severities  = map[string]struct{}{"Minor": {}, "Moderate": {}, "Severe": {}, "Extreme": {}, "Unknown": {}}
	urgencies   = map[string]struct{}{"Immediate": {}, "Expected": {}, "Future": {}, "Past": {}, "Unknown": {}}
	certainties = map[string]struct{}{"Observed": {}, "Likely": {}, "Possible": {}, "Unlikely": {}, "Unknown": {}}
)

// Advisory is the parsed, validated MetoceanAdvisoryIssued primary resource
// plus the envelope binding fields the bridge needs.
type Advisory struct {
	// Envelope binding.
	EventID       string    `json:"event_id"`
	CorrelationID string    `json:"correlation_id"`
	Producer      string    `json:"producer"`
	OccurredAt    time.Time `json:"occurred_at"`

	// CAP 1.2 profile.
	AdvisoryID           string    `json:"advisory_id"`
	Sender               string    `json:"sender"`
	MsgType              string    `json:"msg_type"`
	Category             string    `json:"category"`
	PhenomenonCode       string    `json:"phenomenon_code"`
	Urgency              string    `json:"urgency"`
	Severity             string    `json:"severity"`
	Certainty            string    `json:"certainty"`
	ZoneID               string    `json:"zone_id"`
	EffectiveFrom        time.Time `json:"effective_from"`
	Onset                time.Time `json:"onset"`
	EffectiveUntil       time.Time `json:"effective_until"`
	BulletinReference    string    `json:"bulletin_reference"`
	ReferencesAdvisoryID string    `json:"references_advisory_id"`
	Source               string    `json:"source"`
	AttributionText      string    `json:"attribution_text"`
	Status               string    `json:"status"`
	PolicyDigestSHA256   string    `json:"policy_digest_sha256"`
	IssuedAt             time.Time `json:"issued_at"`
}

// envelopeView mirrors the envelope JSON wire form for parsing after
// signature verification. Unknown members are ignored; required members are
// validated below.
type envelopeView struct {
	EnvelopeVersion string `json:"envelopeVersion"`
	EventID         string `json:"eventId"`
	EventType       string `json:"eventType"`
	OccurredAt      string `json:"occurredAt"`
	Producer        string `json:"producer"`
	CorrelationID   string `json:"correlationId"`
	FHIR            struct {
		ResourceType string `json:"resourceType"`
		Type         string `json:"type"`
		Entry        []struct {
			Resource json.RawMessage `json:"resource"`
		} `json:"entry"`
	} `json:"fhir"`
}

// resourceView mirrors the advisory resource JSON wire form (camelCase).
type resourceView struct {
	Type                 string `json:"@type"`
	AdvisoryID           string `json:"advisoryId"`
	Sender               string `json:"sender"`
	MsgType              string `json:"msgType"`
	Category             string `json:"category"`
	PhenomenonCode       string `json:"phenomenonCode"`
	Urgency              string `json:"urgency"`
	Severity             string `json:"severity"`
	Certainty            string `json:"certainty"`
	ZoneID               string `json:"zoneId"`
	EffectiveFrom        string `json:"effectiveFrom"`
	Onset                string `json:"onset"`
	EffectiveUntil       string `json:"effectiveUntil"`
	BulletinReference    string `json:"bulletinReference"`
	ReferencesAdvisoryID string `json:"referencesAdvisoryId"`
	Source               string `json:"source"`
	FeedKind             string `json:"feedKind"`
	AttributionText      string `json:"attributionText"`
	Status               string `json:"status"`
	PolicyDigestSHA256   string `json:"policyDigestSha256"`
	IssuedAt             string `json:"issuedAt"`
}

// ParseAdvisory decodes and validates one signature-verified advisory
// envelope. It fails closed on any schema or CAP-profile violation: a
// verified-but-malformed advisory is a contract breach and is rejected, never
// partially applied. The caller must have completed signature verification
// first; ParseAdvisory performs no trust decision of its own.
func ParseAdvisory(raw []byte) (Advisory, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var envelope envelopeView
	if err := decoder.Decode(&envelope); err != nil {
		return Advisory{}, fmt.Errorf("decode advisory envelope: %w", err)
	}
	if envelope.EnvelopeVersion != EnvelopeVersion {
		return Advisory{}, fmt.Errorf("envelope version %q is not %q", envelope.EnvelopeVersion, EnvelopeVersion)
	}
	if envelope.EventType != AdvisoryEventType {
		return Advisory{}, fmt.Errorf("envelope event type %q is not %q", envelope.EventType, AdvisoryEventType)
	}
	if envelope.EventID == "" || envelope.CorrelationID == "" {
		return Advisory{}, errors.New("envelope event id and correlation id are required")
	}
	if envelope.FHIR.ResourceType != "Bundle" || envelope.FHIR.Type != "message" {
		return Advisory{}, errors.New("envelope fhir member is not a FHIR message Bundle")
	}
	if len(envelope.FHIR.Entry) != 1 {
		return Advisory{}, fmt.Errorf("advisory bundle must carry exactly one entry, found %d", len(envelope.FHIR.Entry))
	}
	var resource resourceView
	resourceDecoder := json.NewDecoder(bytes.NewReader(envelope.FHIR.Entry[0].Resource))
	resourceDecoder.DisallowUnknownFields()
	if err := resourceDecoder.Decode(&resource); err != nil {
		return Advisory{}, fmt.Errorf("decode advisory resource: %w", err)
	}
	if resource.Type != ResourceType {
		return Advisory{}, fmt.Errorf("advisory resource type %q is not %q", resource.Type, ResourceType)
	}
	advisory := Advisory{
		EventID:              envelope.EventID,
		CorrelationID:        envelope.CorrelationID,
		Producer:             envelope.Producer,
		AdvisoryID:           resource.AdvisoryID,
		Sender:               resource.Sender,
		MsgType:              resource.MsgType,
		Category:             resource.Category,
		PhenomenonCode:       resource.PhenomenonCode,
		Urgency:              resource.Urgency,
		Severity:             resource.Severity,
		Certainty:            resource.Certainty,
		ZoneID:               resource.ZoneID,
		BulletinReference:    resource.BulletinReference,
		ReferencesAdvisoryID: resource.ReferencesAdvisoryID,
		Source:               resource.Source,
		AttributionText:      resource.AttributionText,
		Status:               resource.Status,
		PolicyDigestSHA256:   resource.PolicyDigestSHA256,
	}
	var err error
	if advisory.OccurredAt, err = parseTimestamp("occurredAt", envelope.OccurredAt); err != nil {
		return Advisory{}, err
	}
	if advisory.EffectiveFrom, err = parseTimestamp("effectiveFrom", resource.EffectiveFrom); err != nil {
		return Advisory{}, err
	}
	if advisory.Onset, err = parseTimestamp("onset", resource.Onset); err != nil {
		return Advisory{}, err
	}
	if advisory.EffectiveUntil, err = parseTimestamp("effectiveUntil", resource.EffectiveUntil); err != nil {
		return Advisory{}, err
	}
	if advisory.IssuedAt, err = parseTimestamp("issuedAt", resource.IssuedAt); err != nil {
		return Advisory{}, err
	}
	if err := advisory.Validate(); err != nil {
		return Advisory{}, err
	}
	return advisory, nil
}

// Validate enforces the CAP 1.2 profile invariants (fail closed).
func (advisory Advisory) Validate() error {
	if advisory.AdvisoryID == "" || advisory.Sender == "" || advisory.ZoneID == "" {
		return errors.New("advisory id, sender and zone id are required")
	}
	// category is fixed to "Met" (fail closed otherwise).
	if advisory.Category != "Met" {
		return fmt.Errorf("advisory category %q is not \"Met\"", advisory.Category)
	}
	switch advisory.MsgType {
	case MsgTypeAlert, MsgTypeUpdate:
		if advisory.Status != StatusActive {
			return fmt.Errorf("advisory %s must carry status ACTIVE, found %q", advisory.MsgType, advisory.Status)
		}
	case MsgTypeCancel:
		// Cancel is explicit: it must name the advisory it terminates.
		if advisory.ReferencesAdvisoryID == "" {
			return errors.New("Cancel advisory must carry referencesAdvisoryId")
		}
	default:
		return fmt.Errorf("advisory msgType %q is not Alert, Update or Cancel", advisory.MsgType)
	}
	if advisory.PhenomenonCode == "" {
		return errors.New("advisory phenomenon code is required")
	}
	if _, ok := severities[advisory.Severity]; !ok {
		return fmt.Errorf("advisory severity %q is not a CAP 1.2 severity", advisory.Severity)
	}
	if _, ok := urgencies[advisory.Urgency]; !ok {
		return fmt.Errorf("advisory urgency %q is not a CAP 1.2 urgency", advisory.Urgency)
	}
	if _, ok := certainties[advisory.Certainty]; !ok {
		return fmt.Errorf("advisory certainty %q is not a CAP 1.2 certainty", advisory.Certainty)
	}
	if !advisory.EffectiveFrom.Before(advisory.EffectiveUntil) {
		return errors.New("advisory effectiveFrom must be before effectiveUntil")
	}
	if !strings.HasPrefix(advisory.BulletinReference, "sha256:") || len(advisory.BulletinReference) != len("sha256:")+64 {
		return errors.New("advisory bulletin reference must be a sha256: digest")
	}
	switch advisory.Source {
	case SourceFeed:
		// Licence attribution is mandatory and non-empty for feed-derived
		// advisories.
		if strings.TrimSpace(advisory.AttributionText) == "" {
			return errors.New("feed-derived advisory must carry attribution text")
		}
	case SourceOperatorOverride:
	default:
		return fmt.Errorf("advisory source %q is not FEED or OPERATOR_OVERRIDE", advisory.Source)
	}
	if !strings.HasPrefix(advisory.PolicyDigestSHA256, "sha256:") {
		return errors.New("advisory policy digest must be a sha256: digest")
	}
	return nil
}

func parseTimestamp(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("advisory %s %q is not RFC3339: %w", name, value, err)
	}
	return parsed.UTC(), nil
}
