// Package manifest builds the NIMASA per-departure passenger manifest as a
// FHIR-aligned JSON Bundle (type=collection): a Composition describing the
// voyage plus one anonymized passenger entry per ticketed passenger. No raw
// PII ever appears in the export — passengers are salted HMAC-SHA256 digests,
// matching blueeconomy.contracts.v1.PassengerManifestSubmitted semantics
// (passenger_count must equal the entry count; mismatch fails closed).
package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/ticketing"
)

// Bundle is the FHIR-aligned manifest document.
type Bundle struct {
	ResourceType string  `json:"resourceType"` // fixed "Bundle"
	Type         string  `json:"type"`         // fixed "collection"
	ID           string  `json:"id"`
	Timestamp    string  `json:"timestamp"`
	Entry        []Entry `json:"entry"`
}

// Entry is one bundle entry with a stable fullUrl reference.
type Entry struct {
	FullURL  string `json:"fullUrl"`
	Resource any    `json:"resource"`
}

// Composition is the FHIR-aligned manifest header resource.
type Composition struct {
	ResourceType string        `json:"resourceType"` // "Composition"
	ID           string        `json:"id"`
	Status       string        `json:"status"` // "final"
	Title        string        `json:"title"`
	Date         string        `json:"date"`
	Subject      VoyageSubject `json:"subject"`
	Section      []Section     `json:"section"`
}

// VoyageSubject identifies the voyage without any personal data.
type VoyageSubject struct {
	VesselReference    string `json:"vesselReference"`
	VoyageReference    string `json:"voyageReference"`
	TerminalReference  string `json:"terminalReference"`
	RouteReference     string `json:"routeReference"`
	ScheduledDeparture string `json:"scheduledDeparture"`
}

// Section lists the passenger entry references.
type Section struct {
	Title string           `json:"title"`
	Entry []EntryReference `json:"entry"`
}

// EntryReference points at one bundle entry.
type EntryReference struct {
	Reference string `json:"reference"`
}

// PassengerEntry is the anonymized passenger resource
// (AnonymizedPassengerEntry in manifest.proto).
type PassengerEntry struct {
	ResourceType          string `json:"resourceType"` // "AnonymizedPassengerEntry"
	EntryReference        string `json:"entryReference"`
	PassengerDigestSHA256 string `json:"passengerDigestSha256"`
	Embarked              bool   `json:"embarked"`
}

// Manifest is the persisted export record.
type Manifest struct {
	ManifestID          string
	TripID              string
	OperatorID          string
	VesselReference     string
	TerminalReference   string
	ScheduledDeparture  time.Time
	PassengerCount      int
	ExpectedPassengers  int
	DigestSHA256        string
	ExportedByPrincipal string
	ExportedAt          time.Time
}

// Completeness is the share of expected passengers present on the manifest;
// the platform KPI requires >= 0.95.
func (manifest Manifest) Completeness() float64 {
	if manifest.ExpectedPassengers <= 0 {
		return 1
	}
	return float64(manifest.PassengerCount) / float64(manifest.ExpectedPassengers)
}

// MeetsKPI reports whether the manifest satisfies the completeness KPI.
func (manifest Manifest) MeetsKPI(kpi float64) bool {
	return manifest.Completeness() >= kpi
}

// BuildBundle assembles the FHIR-aligned collection bundle for one trip from
// its PAID/ISSUED tickets. passengerCount is validated against the entry
// count and any mismatch fails closed.
func BuildBundle(manifestID string, trip ticketing.Trip, tickets []ticketing.Ticket, at time.Time) (Bundle, []PassengerEntry, error) {
	if manifestID == "" {
		return Bundle{}, nil, errors.New("manifest id is required")
	}
	if trip.TripID == "" || trip.VesselID == "" || trip.TerminalReference == "" {
		return Bundle{}, nil, errors.New("trip identifiers are required for a manifest")
	}
	passengers := make([]PassengerEntry, 0, len(tickets))
	entries := make([]Entry, 0, len(tickets)+1)
	composition := Composition{
		ResourceType: "Composition",
		ID:           manifestID,
		Status:       "final",
		Title:        "Passenger Manifest",
		Date:         at.UTC().Format(time.RFC3339),
		Subject: VoyageSubject{
			VesselReference:    trip.VesselID,
			VoyageReference:    trip.TripID,
			TerminalReference:  trip.TerminalReference,
			RouteReference:     trip.RouteReference,
			ScheduledDeparture: trip.ScheduledDeparture.UTC().Format(time.RFC3339),
		},
	}
	section := Section{Title: "Passengers", Entry: make([]EntryReference, 0, len(tickets))}
	for _, ticket := range tickets {
		if ticket.State != ticketing.StatePaid && ticket.State != ticketing.StateIssued {
			return Bundle{}, nil, fmt.Errorf("ticket %s in state %s cannot appear on a manifest", ticket.TicketID, ticket.State)
		}
		if ticket.PassengerDigest == "" {
			return Bundle{}, nil, fmt.Errorf("ticket %s has no passenger digest", ticket.TicketID)
		}
		reference := "urn:uuid:" + ticket.TicketID
		passenger := PassengerEntry{
			ResourceType:          "AnonymizedPassengerEntry",
			EntryReference:        reference,
			PassengerDigestSHA256: ticket.PassengerDigest,
			Embarked:              ticket.Embarked,
		}
		passengers = append(passengers, passenger)
		section.Entry = append(section.Entry, EntryReference{Reference: reference})
	}
	composition.Section = []Section{section}
	entries = append(entries, Entry{FullURL: "urn:uuid:" + manifestID, Resource: composition})
	for _, passenger := range passengers {
		entries = append(entries, Entry{FullURL: passenger.EntryReference, Resource: passenger})
	}
	bundle := Bundle{
		ResourceType: "Bundle",
		Type:         "collection",
		ID:           manifestID,
		Timestamp:    at.UTC().Format(time.RFC3339),
		Entry:        entries,
	}
	// manifest.proto invariant: passenger_count must equal the entry count of
	// passenger resources. Fail closed on any drift.
	if len(passengers) != len(tickets) || bundle.PassengerCount() != len(passengers) {
		return Bundle{}, nil, errors.New("manifest passenger count does not equal entry count")
	}
	return bundle, passengers, nil
}

// PassengerCount is the number of AnonymizedPassengerEntry resources in the
// bundle (the Composition header is excluded).
func (bundle Bundle) PassengerCount() int {
	count := 0
	for _, entry := range bundle.Entry {
		if _, ok := entry.Resource.(PassengerEntry); ok {
			count++
		}
	}
	return count
}

// Digest is the SHA-256 digest of the canonical bundle serialization; the raw
// document digest is what the manifest event carries (the raw document is not
// carried on the bus).
func Digest(bundle Bundle) (string, error) {
	canonical, err := json.Marshal(bundle)
	if err != nil {
		return "", fmt.Errorf("canonicalize manifest bundle: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// TripTicketsSource loads the manifestable tickets for one trip.
type TripTicketsSource interface {
	// ManifestTickets returns PAID/ISSUED tickets for the trip.
	ManifestTickets(ctx context.Context, tripID string) ([]ticketing.Ticket, error)
	// RecordManifest persists the export record and its outbox event in one
	// transaction.
	RecordManifest(ctx context.Context, manifest Manifest, event ticketing.Event) error
	// ManifestCompleteness returns (included, expected) for KPI computation.
	ManifestCompleteness(ctx context.Context, operatorID string) (int64, int64, error)
}
