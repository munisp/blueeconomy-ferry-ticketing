package provenance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testKid = "blueeconomy-waterway-safety-0"

func strictSigner(t *testing.T) *Signer {
	t.Helper()
	signer, err := NewSigner(testKid, bytes41())
	require.NoError(t, err)
	return signer
}

// bytes41 is the producer reference test seed (32 bytes of 0x29).
func bytes41() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 41
	}
	return seed
}

func testDirectory(t *testing.T, signer *Signer) *Directory {
	t.Helper()
	raw, err := json.Marshal(map[string]string{signer.KeyID(): signer.PublicKey()})
	require.NoError(t, err)
	directory, err := ParseDirectory(raw)
	require.NoError(t, err)
	return directory
}

func strictEnvelope(t *testing.T, signer *Signer) []byte {
	t.Helper()
	envelope := map[string]any{
		"envelopeVersion": "1.0",
		"eventId":         "evt-1",
		"eventType":       "waterways.met_ocean.advisory.v1",
		"occurredAt":      "2026-08-29T14:00:00Z",
		"producer":        "blueeconomy-waterway-safety",
		"correlationId":   "corr-1",
		"classification":  "INTERNAL",
		"fhir": map[string]any{
			"resourceType": "Bundle",
			"type":         "message",
			"entry":        []any{map[string]any{"resource": map[string]any{"advisoryId": "moa-1"}}},
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

func requireRejection(t *testing.T, err error, reason string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, reason, RejectionReason(err), "error: %v", err)
}

func TestVerifyEnvelopeStrictValid(t *testing.T) {
	signer := strictSigner(t)
	directory := testDirectory(t, signer)
	require.NoError(t, directory.VerifyEnvelopeStrict(strictEnvelope(t, signer)))
}

func TestVerifyEnvelopeStrictTamperedPayload(t *testing.T) {
	signer := strictSigner(t)
	directory := testDirectory(t, signer)
	raw := strictEnvelope(t, signer)
	// Tamper with the envelope after signing: the re-canonicalized payload no
	// longer byte-equals the signed payload segment.
	tampered := strings.Replace(string(raw), `"corr-1"`, `"corr-2"`, 1)
	require.NotEqual(t, string(raw), tampered)
	requireRejection(t, directory.VerifyEnvelopeStrict([]byte(tampered)), ReasonPayloadMismatch)
}

func TestVerifyEnvelopeStrictUnknownKid(t *testing.T) {
	signer := strictSigner(t)
	other, err := NewSigner("blueeconomy-waterway-safety-9", bytes41())
	require.NoError(t, err)
	directory := testDirectory(t, other)
	requireRejection(t, directory.VerifyEnvelopeStrict(strictEnvelope(t, signer)), ReasonUnknownKid)
}

func TestVerifyEnvelopeStrictInvalidSignature(t *testing.T) {
	signer := strictSigner(t)
	directory := testDirectory(t, signer)
	raw := strictEnvelope(t, signer)
	// Re-sign the same payload with a different key under the same kid: the
	// payload matches but the signature is invalid.
	different, err := NewSigner(testKid, make([]byte, ed25519.SeedSize))
	require.NoError(t, err)
	payload, _, err := SignedPayload(raw)
	require.NoError(t, err)
	forged, err := different.Sign(payload)
	require.NoError(t, err)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(raw, &envelope))
	envelope["provenance"].(map[string]any)["signature"] = forged
	forgedRaw, err := json.Marshal(envelope)
	require.NoError(t, err)
	requireRejection(t, directory.VerifyEnvelopeStrict(forgedRaw), ReasonInvalidSignature)
}

func TestVerifyEnvelopeStrictMalformedJWS(t *testing.T) {
	signer := strictSigner(t)
	directory := testDirectory(t, signer)
	cases := map[string]func(raw []byte) []byte{
		"missing signature": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"signature":"`, `"xsignature":"`, 1))
		},
		"two segments": func(raw []byte) []byte {
			return swapSignature(t, raw, "aaa.bbb")
		},
		"empty segment": func(raw []byte) []byte {
			return swapSignature(t, raw, "aaa..ccc")
		},
		"padded segment": func(raw []byte) []byte {
			return swapSignature(t, raw, "YWFh.YmJi.Y2Nj=")
		},
		"header not base64": func(raw []byte) []byte {
			return swapSignature(t, raw, "!!!.YmJi.Y2Nj")
		},
		"header not json": func(raw []byte) []byte {
			return swapSignature(t, raw, base64.RawURLEncoding.EncodeToString([]byte("not-json"))+".YmJi.Y2Nj")
		},
		"bad kid": func(raw []byte) []byte {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":""}`))
			return swapSignature(t, raw, header+".YmJi.Y2Nj")
		},
		"not json": func(raw []byte) []byte {
			return []byte("{not json")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			requireRejection(t, directory.VerifyEnvelopeStrict(mutate(strictEnvelope(t, signer))), ReasonMalformedJWS)
		})
	}
}

func TestVerifyEnvelopeStrictUnsupportedAlg(t *testing.T) {
	signer := strictSigner(t)
	directory := testDirectory(t, signer)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + testKid + `"}`))
	raw := swapSignature(t, strictEnvelope(t, signer), header+".YmJi.Y2Nj")
	requireRejection(t, directory.VerifyEnvelopeStrict(raw), ReasonUnsupportedAlg)
}

// swapSignature replaces the provenance signature value in a raw envelope.
func swapSignature(t *testing.T, raw []byte, signature string) []byte {
	t.Helper()
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(raw, &envelope))
	envelope["provenance"].(map[string]any)["signature"] = signature
	mutated, err := json.Marshal(envelope)
	require.NoError(t, err)
	return mutated
}

func TestRejectionErrorText(t *testing.T) {
	rejection := &Rejection{Reason: ReasonUnknownKid, Details: "kid x"}
	require.Contains(t, rejection.Error(), ReasonUnknownKid)
	require.Equal(t, "", RejectionReason(nil))
	require.Equal(t, "", RejectionReason(json.Unmarshal([]byte("{"), new(any))))
}
