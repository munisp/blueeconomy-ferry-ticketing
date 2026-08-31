package metocean

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-ferry-ticketing/internal/provenance"
)

// advisory_envelope.json is the synthetic, schema-valid contract fixture
// (blueeconomy-contracts fixtures/metocean/waterways.met_ocean.advisory.v1.json).
func fixtureEnvelope(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/advisory_envelope.json")
	require.NoError(t, err)
	return raw
}

func TestParseAdvisoryFixture(t *testing.T) {
	advisory, err := ParseAdvisory(fixtureEnvelope(t))
	require.NoError(t, err)
	require.Equal(t, "moa-2026-000123", advisory.AdvisoryID)
	require.Equal(t, "evt-metocean-000001", advisory.EventID)
	require.Equal(t, "corr-metocean-000001", advisory.CorrelationID)
	require.Equal(t, AdvisoryProducer, advisory.Producer)
	require.Equal(t, MsgTypeAlert, advisory.MsgType)
	require.Equal(t, "Met", advisory.Category)
	require.Equal(t, "Severe", advisory.Severity)
	require.Equal(t, "hz-lagos-approach", advisory.ZoneID)
	require.Equal(t, StatusActive, advisory.Status)
	require.Equal(t, SourceFeed, advisory.Source)
	require.Equal(t, "Weather data by Open-Meteo.com", advisory.AttributionText)
	require.Equal(t, time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC), advisory.EffectiveFrom)
	require.Equal(t, time.Date(2026, 8, 30, 6, 0, 0, 0, time.UTC), advisory.EffectiveUntil)
	require.True(t, strings.HasPrefix(advisory.BulletinReference, "sha256:"))
}

// TestFixturePayloadIsCanonical pins the cross-language JCS contract: the
// producer's signed payload segment must byte-equal this repository's RFC
// 8785 canonicalization of the fixture envelope minus provenance.signature.
func TestFixturePayloadIsCanonical(t *testing.T) {
	raw := fixtureEnvelope(t)
	canonical, signature, err := provenance.SignedPayload(raw)
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	segments := strings.Split(signature, ".")
	require.Len(t, segments, 3)
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	require.NoError(t, err)
	require.JSONEq(t, string(payload), string(canonical))
	require.Equal(t, string(payload), string(canonical))
}

// mutateFixture decodes the fixture, applies mutate to the resource member
// and re-encodes the envelope (signature left stale; ParseAdvisory performs
// no trust decision, so structural mutations suffice).
func mutateFixture(t *testing.T, mutate func(resource map[string]any)) []byte {
	t.Helper()
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(fixtureEnvelope(t), &envelope))
	entry := envelope["fhir"].(map[string]any)["entry"].([]any)
	resource := entry[0].(map[string]any)["resource"].(map[string]any)
	mutate(resource)
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	return raw
}

func TestParseAdvisoryValidation(t *testing.T) {
	cases := map[string]func(resource map[string]any){
		"category fixed to Met": func(resource map[string]any) {
			resource["category"] = "Other"
		},
		"cancel requires reference": func(resource map[string]any) {
			resource["msgType"] = "Cancel"
			resource["status"] = "CANCELLED"
			resource["referencesAdvisoryId"] = ""
		},
		"unknown severity": func(resource map[string]any) {
			resource["severity"] = "Catastrophic"
		},
		"unknown urgency": func(resource map[string]any) {
			resource["urgency"] = "Whenever"
		},
		"unknown certainty": func(resource map[string]any) {
			resource["certainty"] = "Maybe"
		},
		"empty window": func(resource map[string]any) {
			resource["effectiveUntil"] = resource["effectiveFrom"]
		},
		"feed requires attribution": func(resource map[string]any) {
			resource["attributionText"] = ""
		},
		"bulletin digest required": func(resource map[string]any) {
			resource["bulletinReference"] = "md5:abc"
		},
		"alert must be active": func(resource map[string]any) {
			resource["status"] = "CANCELLED"
		},
		"zone required": func(resource map[string]any) {
			resource["zoneId"] = ""
		},
		"bad timestamp": func(resource map[string]any) {
			resource["effectiveFrom"] = "tomorrow"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAdvisory(mutateFixture(t, mutate))
			require.Error(t, err)
		})
	}
}

func TestParseAdvisoryCancel(t *testing.T) {
	raw := mutateFixture(t, func(resource map[string]any) {
		resource["msgType"] = "Cancel"
		resource["status"] = "CANCELLED"
		resource["referencesAdvisoryId"] = "moa-2026-000123"
	})
	advisory, err := ParseAdvisory(raw)
	require.NoError(t, err)
	require.Equal(t, MsgTypeCancel, advisory.MsgType)
	require.Equal(t, "moa-2026-000123", advisory.ReferencesAdvisoryID)
}

func TestParseAdvisoryEnvelopeChecks(t *testing.T) {
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(fixtureEnvelope(t), &envelope))

	wrongType, err := json.Marshal(map[string]any{"envelopeVersion": "1.0", "eventType": "other.v1"})
	require.NoError(t, err)
	_, err = ParseAdvisory(wrongType)
	require.Error(t, err)

	envelope["eventType"] = "waterways.met_ocean.advisory.v0"
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	_, err = ParseAdvisory(raw)
	require.Error(t, err)

	envelope["eventType"] = AdvisoryEventType
	envelope["envelopeVersion"] = "2.0"
	raw, err = json.Marshal(envelope)
	require.NoError(t, err)
	_, err = ParseAdvisory(raw)
	require.Error(t, err)
}
