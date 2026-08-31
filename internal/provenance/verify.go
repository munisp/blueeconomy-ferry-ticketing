package provenance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Consumer-side envelope verification per docs/envelope-signature.md §4.
// VerifyEnvelopeStrict implements the fail-closed algorithm with the
// normative rejection reason codes; rejected envelopes must never be
// persisted or forwarded, and there is no unsigned admission path.

// Rejection reason codes (normative, docs/envelope-signature.md §4.6).
const (
	// ReasonMalformedJWS: the signature is absent, not a string, or not
	// three non-empty base64url segments with a decodable header.
	ReasonMalformedJWS = "malformed-jws"
	// ReasonUnsupportedAlg: the protected header alg is not "EdDSA".
	ReasonUnsupportedAlg = "unsupported-alg"
	// ReasonUnknownKid: the key id is not present in the key directory.
	ReasonUnknownKid = "unknown-kid"
	// ReasonPayloadMismatch: the decoded JWS payload does not byte-equal the
	// RFC 8785 canonicalization of the envelope minus provenance.signature.
	ReasonPayloadMismatch = "payload-mismatch"
	// ReasonInvalidSignature: Ed25519 verification failed.
	ReasonInvalidSignature = "invalid-signature"
)

// Rejection is a terminal envelope verification failure carrying the
// normative reason code for logging and metering.
type Rejection struct {
	Reason  string
	Details string
}

// Error implements error.
func (rejection *Rejection) Error() string {
	if rejection.Details == "" {
		return "envelope rejected: " + rejection.Reason
	}
	return "envelope rejected: " + rejection.Reason + ": " + rejection.Details
}

// reject builds one Rejection.
func reject(reason, format string, args ...any) *Rejection {
	return &Rejection{Reason: reason, Details: fmt.Sprintf(format, args...)}
}

// RejectionReason extracts the normative reason code from an error returned
// by VerifyEnvelopeStrict, or "" when err is nil or not a Rejection.
func RejectionReason(err error) string {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Reason
	}
	return ""
}

// VerifyEnvelopeStrict verifies one raw envelope document per the normative
// consumer algorithm:
//
//  1. provenance.signature must be a string of three non-empty base64url
//     segments (padding prohibited);
//  2. the protected header must be exactly {"alg":"EdDSA","kid":<kid>} with
//     a well-formed kid;
//  3. the kid must resolve in the key directory;
//  4. the decoded payload segment must byte-equal the RFC 8785 JCS of the
//     envelope minus provenance.signature;
//  5. the Ed25519 signature over segment1 + "." + segment2 must verify.
//
// Every failure is a *Rejection with the normative reason code; rejection is
// terminal — there is no retry, fallback or unsigned admission path.
func (d *Directory) VerifyEnvelopeStrict(raw []byte) error {
	if d == nil {
		return reject(ReasonUnknownKid, "key directory is required")
	}
	document, err := decodeJSON(raw)
	if err != nil {
		return reject(ReasonMalformedJWS, "envelope is not valid JSON: %v", err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return reject(ReasonMalformedJWS, "envelope is not a JSON object")
	}
	provenanceMember, ok := object["provenance"].(map[string]any)
	if !ok {
		return reject(ReasonMalformedJWS, "envelope provenance is not a JSON object")
	}
	signature, ok := provenanceMember["signature"].(string)
	if !ok || signature == "" {
		return reject(ReasonMalformedJWS, "envelope provenance signature is missing or not a string")
	}

	headerSegment, payloadSegment, signatureSegment, header, err := parseJWSStrict(signature)
	if err != nil {
		return err
	}
	publicKey, ok := d.keys[header.kid]
	if !ok {
		return reject(ReasonUnknownKid, "unknown provenance key id %q", header.kid)
	}

	// Byte-exact payload match: the decoded payload segment must equal the
	// re-canonicalized envelope minus provenance.signature.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return reject(ReasonMalformedJWS, "JWS payload segment is not base64url: %v", err)
	}
	delete(provenanceMember, "signature")
	canonical, err := Canonicalize(document)
	if err != nil {
		return reject(ReasonPayloadMismatch, "canonicalize envelope: %v", err)
	}
	if !bytes.Equal(payloadBytes, canonical) {
		return reject(ReasonPayloadMismatch, "JWS payload does not byte-equal the canonicalized envelope")
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return reject(ReasonMalformedJWS, "JWS signature segment is not a base64url Ed25519 signature")
	}
	if !ed25519.Verify(publicKey, []byte(headerSegment+"."+payloadSegment), signatureBytes) {
		return reject(ReasonInvalidSignature, "Ed25519 signature verification failed for kid %q", header.kid)
	}
	return nil
}

// jwsHeader is the strict protected header: exactly alg and kid.
type jwsHeader struct {
	kid string
}

// parseJWSStrict decodes and validates the JWS compact serialization per
// steps 1-2 of the consumer algorithm: three non-empty unpadded base64url
// segments, a protected header with exactly {"alg":"EdDSA","kid":<kid>} and
// a well-formed kid.
func parseJWSStrict(jws string) (headerSegment, payloadSegment, signatureSegment string, header jwsHeader, err error) {
	segments := strings.Split(jws, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return "", "", "", header, reject(ReasonMalformedJWS, "JWS compact serialization must have three non-empty segments")
	}
	for _, segment := range segments {
		if strings.Contains(segment, "=") {
			return "", "", "", header, reject(ReasonMalformedJWS, "JWS segments must be unpadded base64url")
		}
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "", "", "", header, reject(ReasonMalformedJWS, "JWS protected header is not base64url: %v", err)
	}
	var decoded struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	decoder := json.NewDecoder(bytes.NewReader(headerRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return "", "", "", header, reject(ReasonMalformedJWS, "JWS protected header is invalid: %v", err)
	}
	if decoder.More() {
		return "", "", "", header, reject(ReasonMalformedJWS, "JWS protected header has trailing data")
	}
	if decoded.Alg != Algorithm {
		return "", "", "", header, reject(ReasonUnsupportedAlg, "JWS algorithm %q is not %q", decoded.Alg, Algorithm)
	}
	if err := validateKid(decoded.Kid); err != nil {
		return "", "", "", header, reject(ReasonMalformedJWS, "JWS key id: %v", err)
	}
	return segments[0], segments[1], segments[2], jwsHeader{kid: decoded.Kid}, nil
}
