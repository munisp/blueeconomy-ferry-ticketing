// Package passproof implements the signed pass artifact (BFP1): an
// Ed25519-signed, QR-encodable credential proving a BlueFare pass or
// capped-account entitlement offline. Verification needs only the cached
// public key directory (pass_validation_keys): signature, key id, key epoch
// and the validity window are all inside the signed payload, so conductor
// devices admit/deny with zero connectivity and catch revocations through
// the signed blocklist delta.
//
// Unlike single-journey ticket artifacts (BET1), passes are long-lived
// bearer credentials presented many times over their validity window, so
// there is no rotating anti-screenshot window code: replay resistance comes
// from server-side first-scan-wins on seat tickets and from pass-back
// heuristics on the conductor device, not from the credential.
//
// Wire format v1 (all integers big-endian, all bytes concatenated):
//
//	payload:
//	  magic           4 bytes   "BFP1"
//	  kid             8 bytes   SHA-256(ed25519 public key)[0:8]
//	  pass_id         u8 length-prefixed UTF-8
//	  product_id      u8 length-prefixed UTF-8
//	  scope_type      u8        (1=ROUTE, 2=ZONE, 3=NETWORK)
//	  scope_ref       u8 length-prefixed UTF-8 ('' for NETWORK)
//	  valid_from      i64       unix seconds
//	  valid_to        i64       unix seconds
//	  key_epoch       u32       validation-key epoch (devices reject epochs
//	                            ahead of their cached directory)
//	  holder_digest   32 bytes  raw HMAC-SHA256 salted owner digest
//	artifact = payload || ed25519_signature(payload) 64 bytes
//	token    = base64url-no-pad(artifact)              (QR alphabet safe)
package passproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// WireFormatVersion is the artifact magic, "BFP1".
const WireFormatVersion = "BFP1"

const (
	kidLength       = 8
	signatureLength = ed25519.SignatureSize
	digestLength    = sha256.Size
	maxIDLength     = 128
)

// Scope types carried by the artifact.
const (
	ScopeRoute   uint8 = 1
	ScopeZone    uint8 = 2
	ScopeNetwork uint8 = 3
)

var (
	// ErrMalformedArtifact rejects undecodable or truncated tokens.
	ErrMalformedArtifact = errors.New("pass artifact is malformed")
	// ErrUnknownKeyID rejects artifacts signed by a key outside the trusted set.
	ErrUnknownKeyID = errors.New("pass artifact key id is not trusted")
	// ErrInvalidSignature rejects artifacts whose Ed25519 signature does not verify.
	ErrInvalidSignature = errors.New("pass artifact signature is invalid")
	// ErrNotValidYet rejects artifacts before valid_from.
	ErrNotValidYet = errors.New("pass is not valid yet")
	// ErrExpired rejects artifacts past valid_to.
	ErrExpired = errors.New("pass has expired")
)

// FailureReason maps a verification error to a stable, PII-free telemetry code.
func FailureReason(err error) string {
	switch {
	case errors.Is(err, ErrUnknownKeyID):
		return "unknown_kid"
	case errors.Is(err, ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, ErrNotValidYet):
		return "not_valid_yet"
	case errors.Is(err, ErrExpired):
		return "expired"
	default:
		return "malformed"
	}
}

// Payload is the parsed, canonical content of a signed pass artifact.
type Payload struct {
	KeyID        string // base64url of the 8 raw kid bytes
	PassID       string
	ProductID    string
	ScopeType    uint8
	ScopeRef     string
	ValidFrom    time.Time
	ValidTo      time.Time
	KeyEpoch     uint32
	HolderDigest string // hex HMAC-SHA256 salted owner digest
}

// ScopeName renders the wire scope code.
func ScopeName(scopeType uint8) string {
	switch scopeType {
	case ScopeRoute:
		return "ROUTE"
	case ScopeZone:
		return "ZONE"
	case ScopeNetwork:
		return "NETWORK"
	}
	return ""
}

// ScopeCode parses a scope name, failing closed on anything unknown.
func ScopeCode(name string) (uint8, error) {
	switch name {
	case "ROUTE":
		return ScopeRoute, nil
	case "ZONE":
		return ScopeZone, nil
	case "NETWORK":
		return ScopeNetwork, nil
	}
	return 0, fmt.Errorf("scope type %q is not supported", name)
}

// marshal renders the canonical signed bytes.
func (payload Payload) marshal(kidRaw []byte) ([]byte, error) {
	if len(kidRaw) != kidLength {
		return nil, errors.New("kid must be 8 raw bytes")
	}
	if len(payload.PassID) == 0 || len(payload.PassID) > maxIDLength || len(payload.ProductID) == 0 || len(payload.ProductID) > maxIDLength {
		return nil, errors.New("pass and product ids are required and must be at most 128 bytes")
	}
	if len(payload.ScopeRef) > maxIDLength {
		return nil, errors.New("scope reference must be at most 128 bytes")
	}
	if ScopeName(payload.ScopeType) == "" {
		return nil, errors.New("scope type is required")
	}
	holderRaw, err := hex.DecodeString(payload.HolderDigest)
	if err != nil || len(holderRaw) != digestLength {
		return nil, errors.New("holder digest must be a hex-encoded SHA-256 digest")
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	buffer.WriteString(WireFormatVersion)
	buffer.Write(kidRaw)
	buffer.WriteByte(byte(len(payload.PassID)))
	buffer.WriteString(payload.PassID)
	buffer.WriteByte(byte(len(payload.ProductID)))
	buffer.WriteString(payload.ProductID)
	buffer.WriteByte(payload.ScopeType)
	buffer.WriteByte(byte(len(payload.ScopeRef)))
	buffer.WriteString(payload.ScopeRef)
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:8], uint64(payload.ValidFrom.Unix()))
	buffer.Write(fixed[:8])
	binary.BigEndian.PutUint64(fixed[:8], uint64(payload.ValidTo.Unix()))
	buffer.Write(fixed[:8])
	binary.BigEndian.PutUint32(fixed[:4], payload.KeyEpoch)
	buffer.Write(fixed[:4])
	buffer.Write(holderRaw)
	return buffer.Bytes(), nil
}

// parsePayload splits a decoded artifact into payload bytes, parsed fields
// and signature. It never panics on short input.
func parsePayload(raw []byte) (Payload, []byte, []byte, error) {
	fixed := len(WireFormatVersion) + kidLength + 1 + 1 + 1 + 1 + 8 + 8 + 4 + digestLength
	if len(raw) < fixed+signatureLength {
		return Payload{}, nil, nil, ErrMalformedArtifact
	}
	if string(raw[:4]) != WireFormatVersion {
		return Payload{}, nil, nil, ErrMalformedArtifact
	}
	signatureAt := len(raw) - signatureLength
	payloadBytes, signature := raw[:signatureAt], raw[signatureAt:]
	cursor := 4
	kidRaw := payloadBytes[cursor : cursor+kidLength]
	cursor += kidLength
	readString := func(allowEmpty bool) (string, error) {
		if cursor >= len(payloadBytes) {
			return "", ErrMalformedArtifact
		}
		length := int(payloadBytes[cursor])
		cursor++
		if cursor+length > len(payloadBytes) {
			return "", ErrMalformedArtifact
		}
		if length == 0 && !allowEmpty {
			return "", ErrMalformedArtifact
		}
		value := string(payloadBytes[cursor : cursor+length])
		cursor += length
		return value, nil
	}
	passID, err := readString(false)
	if err != nil {
		return Payload{}, nil, nil, err
	}
	productID, err := readString(false)
	if err != nil {
		return Payload{}, nil, nil, err
	}
	if cursor >= len(payloadBytes) {
		return Payload{}, nil, nil, ErrMalformedArtifact
	}
	scopeType := payloadBytes[cursor]
	cursor++
	if ScopeName(scopeType) == "" {
		return Payload{}, nil, nil, ErrMalformedArtifact
	}
	scopeRef, err := readString(true)
	if err != nil {
		return Payload{}, nil, nil, err
	}
	if cursor+8+8+4+digestLength != len(payloadBytes) {
		return Payload{}, nil, nil, ErrMalformedArtifact
	}
	validFrom := int64(binary.BigEndian.Uint64(payloadBytes[cursor : cursor+8]))
	cursor += 8
	validTo := int64(binary.BigEndian.Uint64(payloadBytes[cursor : cursor+8]))
	cursor += 8
	epoch := binary.BigEndian.Uint32(payloadBytes[cursor : cursor+4])
	cursor += 4
	holder := payloadBytes[cursor : cursor+digestLength]
	return Payload{
		KeyID:        base64.RawURLEncoding.EncodeToString(kidRaw),
		PassID:       passID,
		ProductID:    productID,
		ScopeType:    scopeType,
		ScopeRef:     scopeRef,
		ValidFrom:    time.Unix(validFrom, 0).UTC(),
		ValidTo:      time.Unix(validTo, 0).UTC(),
		KeyEpoch:     epoch,
		HolderDigest: hex.EncodeToString(holder),
	}, payloadBytes, signature, nil
}

// KeyID derives the raw 8-byte kid of a public key.
func KeyID(public ed25519.PublicKey) []byte {
	digest := sha256.Sum256(public)
	return digest[:kidLength]
}

// KeyIDString renders the kid in the base64url form used on the wire.
func KeyIDString(public ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(KeyID(public))
}

// Signer signs pass artifacts with the current validation key. Constructed
// from env-injected key material; there are no defaults and no fabricated keys.
type Signer struct {
	current ed25519.PrivateKey
	epoch   uint32
}

// NewSigner fails closed on malformed key material.
func NewSigner(current ed25519.PrivateKey, epoch uint32) (*Signer, error) {
	if len(current) != ed25519.PrivateKeySize {
		return nil, errors.New("current ed25519 private key is required (fail-closed)")
	}
	if epoch == 0 {
		return nil, errors.New("validation key epoch must be at least 1")
	}
	return &Signer{current: current, epoch: epoch}, nil
}

// Public returns the current public key.
func (signer *Signer) Public() ed25519.PublicKey {
	return signer.current.Public().(ed25519.PublicKey)
}

// Epoch returns the current validation key epoch.
func (signer *Signer) Epoch() uint32 { return signer.epoch }

// Sign renders and signs the payload with the current key and epoch.
func (signer *Signer) Sign(payload Payload, at time.Time) (string, error) {
	public := signer.current.Public().(ed25519.PublicKey)
	payload.KeyEpoch = signer.epoch
	if payload.ValidFrom.IsZero() || payload.ValidTo.IsZero() || !payload.ValidTo.After(payload.ValidFrom) {
		return "", errors.New("valid_from must precede valid_to")
	}
	canonical, err := payload.marshal(KeyID(public))
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(signer.current, canonical)
	artifact := make([]byte, 0, len(canonical)+signatureLength)
	artifact = append(artifact, canonical...)
	artifact = append(artifact, signature...)
	return base64.RawURLEncoding.EncodeToString(artifact), nil
}

// TrustedKey is one entry of the distributable validation key directory
// (pass_validation_keys). Devices cache the directory and reject artifacts
// whose epoch has no matching key.
type TrustedKey struct {
	KeyID  string // base64url kid
	Public ed25519.PublicKey
	Epoch  uint32
}

// Verifier verifies pass artifacts against a cached trusted key directory.
// It is pure: no database, network or hidden clock — exactly what an offline
// conductor device embeds.
type Verifier struct {
	keys map[uint32]TrustedKey // epoch -> key
}

// NewVerifier fails closed on an empty or malformed directory.
func NewVerifier(keys []TrustedKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one trusted validation key is required (fail-closed)")
	}
	verifier := &Verifier{keys: make(map[uint32]TrustedKey, len(keys))}
	for _, key := range keys {
		if len(key.Public) != ed25519.PublicKeySize || key.Epoch == 0 {
			return nil, errors.New("trusted keys require a 32-byte public key and a positive epoch")
		}
		verifier.keys[key.Epoch] = key
	}
	return verifier, nil
}

// CurrentEpoch returns the highest trusted epoch (the directory head).
func (verifier *Verifier) CurrentEpoch() uint32 {
	var head uint32
	for epoch := range verifier.keys {
		if epoch > head {
			head = epoch
		}
	}
	return head
}

// Verify decodes the token, resolves the payload's key epoch against the
// cached directory and verifies the Ed25519 signature. Temporal validity is
// reported, not enforced: callers combine the signature result with their
// own clock and the blocklist to reach ADMIT/DENY, so a wrong-epoch or
// bad-signature artifact is always a hard failure while not_valid_yet and
// expired are policy decisions of the caller.
func (verifier *Verifier) Verify(token string) (Payload, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Payload{}, ErrMalformedArtifact
	}
	payload, payloadBytes, signature, err := parsePayload(raw)
	if err != nil {
		return Payload{}, err
	}
	key, ok := verifier.keys[payload.KeyEpoch]
	if !ok {
		return payload, ErrUnknownKeyID
	}
	if payload.KeyID != key.KeyID {
		return payload, ErrUnknownKeyID
	}
	if !ed25519.Verify(key.Public, payloadBytes, signature) {
		return payload, ErrInvalidSignature
	}
	return payload, nil
}

// VerifyBlocklist verifies a signed blocklist delta page against the current
// directory head. The canonical signed bytes are:
//
//	"BFB1" || u32 epoch || u64 since_unix || u16 count || pass_ids (u8 len-prefixed)
func (verifier *Verifier) VerifyBlocklist(epoch uint32, sinceUnix int64, passIDs []string, signatureHex string) error {
	key, ok := verifier.keys[epoch]
	if !ok {
		return ErrUnknownKeyID
	}
	if epoch != verifier.CurrentEpoch() {
		return ErrUnknownKeyID
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != signatureLength {
		return ErrMalformedArtifact
	}
	canonical, err := BlocklistCanonical(epoch, sinceUnix, passIDs)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key.Public, canonical, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// BlocklistCanonical renders the canonical bytes a blocklist delta page signs.
func BlocklistCanonical(epoch uint32, sinceUnix int64, passIDs []string) ([]byte, error) {
	if epoch == 0 {
		return nil, errors.New("epoch must be at least 1")
	}
	if len(passIDs) > 65535 {
		return nil, errors.New("blocklist page exceeds 65535 entries")
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 64+32*len(passIDs)))
	buffer.WriteString("BFB1")
	var fixed [8]byte
	binary.BigEndian.PutUint32(fixed[:4], epoch)
	buffer.Write(fixed[:4])
	binary.BigEndian.PutUint64(fixed[:8], uint64(sinceUnix))
	buffer.Write(fixed[:8])
	binary.BigEndian.PutUint16(fixed[:2], uint16(len(passIDs)))
	buffer.Write(fixed[:2])
	for _, passID := range passIDs {
		if len(passID) == 0 || len(passID) > maxIDLength {
			return nil, errors.New("blocklist pass ids must be 1..128 bytes")
		}
		buffer.WriteByte(byte(len(passID)))
		buffer.WriteString(passID)
	}
	return buffer.Bytes(), nil
}

// SignBlocklist signs one blocklist delta page with the current key.
func (signer *Signer) SignBlocklist(sinceUnix int64, passIDs []string) (string, error) {
	canonical, err := BlocklistCanonical(signer.epoch, sinceUnix, passIDs)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(signer.current, canonical)), nil
}
