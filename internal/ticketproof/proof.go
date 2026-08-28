// Package ticketproof implements the signed ticket artifact: an
// Ed25519-signed, QR-encodable capability that proves a ticket's authenticity
// offline (signature + key-id + rotation epoch need only the public key set)
// plus a TOTP-style rotating window code that expires static screenshots.
//
// The package is pure: no database, network or clock dependency is hidden —
// every verification takes an explicit `now` so the future mobile app can
// embed byte-identical offline verification.
//
// Wire format v1 (all integers big-endian, all bytes concatenated):
//
//	payload:
//	  magic           4 bytes   "BET1"
//	  kid             8 bytes   SHA-256(ed25519 public key)[0:8]
//	  ticket_id       u8 length-prefixed UTF-8
//	  trip_id         u8 length-prefixed UTF-8
//	  seat            u16       (0 = unassigned)
//	  issued_at       i64       unix seconds
//	  expires_at      i64       unix seconds (artifact void afterwards)
//	  rotation_epoch  u32       signing-key epoch, monotonic per rotation
//	  holder_digest   32 bytes  raw HMAC-SHA256 salted passenger digest
//	artifact = payload || ed25519_signature(payload) 64 bytes || window_code 8 bytes
//	token    = base64url-no-pad(artifact)            (QR alphabet safe)
//
// kid scheme: the first 8 bytes of the SHA-256 digest of the Ed25519 public
// key. Rotation mirrors the maritime-intelligence feed pattern: the current
// key signs, the immediately previous key is accepted until its grace
// deadline, anything else fails closed.
//
// Rotating window code (30-second step, +/-1 window tolerance):
//
//	window_secret = HMAC-SHA256(server_window_secret, "BET1-window" || ticket_id)
//	window_code   = HMAC-SHA256(window_secret, u64(unix/30))[0:8]
//
// The window secret is derived from the ticket ID and the server secret at
// verification time, so no per-ticket secret is ever stored. The window code
// sits outside the signed payload (it rotates); authenticity comes from the
// signature, replay-resistance from the code.
package ticketproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WireFormatVersion is the artifact magic, "BET1".
const WireFormatVersion = "BET1"

const (
	kidLength        = 8
	signatureLength  = ed25519.SignatureSize
	windowCodeLength = 8
	digestLength     = sha256.Size
	// WindowStepSeconds is the TOTP-style window step.
	WindowStepSeconds = 30
	// WindowTolerance is the number of windows accepted on either side of
	// the current one (+/-1 => a screenshot lives at most ~90 seconds).
	WindowTolerance = 1
	maxIDLength     = 128
)

var (
	// ErrMalformedArtifact rejects undecodable or truncated tokens.
	ErrMalformedArtifact = errors.New("ticket artifact is malformed")
	// ErrUnknownKeyID rejects artifacts signed by a key outside the trusted set.
	ErrUnknownKeyID = errors.New("ticket artifact key id is not trusted")
	// ErrRotationGraceExpired rejects previous-key artifacts after the grace deadline.
	ErrRotationGraceExpired = errors.New("ticket artifact signing key rotation grace has expired")
	// ErrInvalidSignature rejects artifacts whose Ed25519 signature does not verify.
	ErrInvalidSignature = errors.New("ticket artifact signature is invalid")
	// ErrArtifactExpired rejects artifacts past their expires_at.
	ErrArtifactExpired = errors.New("ticket artifact has expired")
	// ErrWindowCodeInvalid rejects stale or forged rotating window codes.
	ErrWindowCodeInvalid = errors.New("ticket artifact window code is outside the accepted tolerance")
)

// FailureReason maps a verification error to a stable, PII-free telemetry
// code for the security-operations fraud signal.
func FailureReason(err error) string {
	switch {
	case errors.Is(err, ErrUnknownKeyID):
		return "unknown_kid"
	case errors.Is(err, ErrRotationGraceExpired):
		return "rotation_grace_expired"
	case errors.Is(err, ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, ErrArtifactExpired):
		return "artifact_expired"
	case errors.Is(err, ErrWindowCodeInvalid):
		return "window_code_invalid"
	default:
		return "malformed"
	}
}

// Payload is the parsed, canonical content of a signed ticket artifact.
type Payload struct {
	KeyID         string // base64url of the 8 raw kid bytes
	TicketID      string
	TripID        string
	Seat          int
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RotationEpoch uint32
	HolderDigest  string // hex HMAC-SHA256 salted passenger digest
}

// marshal renders the canonical signed bytes.
func (payload Payload) marshal(kidRaw []byte) ([]byte, error) {
	if len(kidRaw) != kidLength {
		return nil, errors.New("kid must be 8 raw bytes")
	}
	if len(payload.TicketID) == 0 || len(payload.TicketID) > maxIDLength || len(payload.TripID) == 0 || len(payload.TripID) > maxIDLength {
		return nil, errors.New("ticket and trip ids are required and must be at most 128 bytes")
	}
	if payload.Seat < 0 || payload.Seat > 65535 {
		return nil, errors.New("seat must fit in a uint16")
	}
	holderRaw, err := hex.DecodeString(payload.HolderDigest)
	if err != nil || len(holderRaw) != digestLength {
		return nil, errors.New("holder digest must be a hex-encoded SHA-256 digest")
	}
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	buffer.WriteString(WireFormatVersion)
	buffer.Write(kidRaw)
	buffer.WriteByte(byte(len(payload.TicketID)))
	buffer.WriteString(payload.TicketID)
	buffer.WriteByte(byte(len(payload.TripID)))
	buffer.WriteString(payload.TripID)
	var fixed [8]byte
	binary.BigEndian.PutUint16(fixed[:2], uint16(payload.Seat))
	buffer.Write(fixed[:2])
	binary.BigEndian.PutUint64(fixed[:8], uint64(payload.IssuedAt.Unix()))
	buffer.Write(fixed[:8])
	binary.BigEndian.PutUint64(fixed[:8], uint64(payload.ExpiresAt.Unix()))
	buffer.Write(fixed[:8])
	binary.BigEndian.PutUint32(fixed[:4], payload.RotationEpoch)
	buffer.Write(fixed[:4])
	buffer.Write(holderRaw)
	return buffer.Bytes(), nil
}

// parsePayload splits a decoded artifact into its payload bytes, parsed
// fields, signature and window code. It never panics on short input.
func parsePayload(raw []byte) (Payload, []byte, []byte, []byte, error) {
	if len(raw) < len(WireFormatVersion)+kidLength+2+8+8+4+digestLength+signatureLength+windowCodeLength {
		return Payload{}, nil, nil, nil, ErrMalformedArtifact
	}
	if string(raw[:4]) != WireFormatVersion {
		return Payload{}, nil, nil, nil, ErrMalformedArtifact
	}
	signatureAt := len(raw) - signatureLength - windowCodeLength
	payloadBytes, signature, windowCode := raw[:signatureAt], raw[signatureAt:signatureAt+signatureLength], raw[signatureAt+signatureLength:]
	cursor := 4
	kidRaw := payloadBytes[cursor : cursor+kidLength]
	cursor += kidLength
	readID := func() (string, error) {
		if cursor >= len(payloadBytes) {
			return "", ErrMalformedArtifact
		}
		length := int(payloadBytes[cursor])
		cursor++
		if length == 0 || cursor+length > len(payloadBytes) {
			return "", ErrMalformedArtifact
		}
		value := string(payloadBytes[cursor : cursor+length])
		cursor += length
		return value, nil
	}
	ticketID, err := readID()
	if err != nil {
		return Payload{}, nil, nil, nil, err
	}
	tripID, err := readID()
	if err != nil {
		return Payload{}, nil, nil, nil, err
	}
	if cursor+2+8+8+4+digestLength != len(payloadBytes) {
		return Payload{}, nil, nil, nil, ErrMalformedArtifact
	}
	seat := int(binary.BigEndian.Uint16(payloadBytes[cursor : cursor+2]))
	cursor += 2
	issuedAt := int64(binary.BigEndian.Uint64(payloadBytes[cursor : cursor+8]))
	cursor += 8
	expiresAt := int64(binary.BigEndian.Uint64(payloadBytes[cursor : cursor+8]))
	cursor += 8
	epoch := binary.BigEndian.Uint32(payloadBytes[cursor : cursor+4])
	cursor += 4
	holder := payloadBytes[cursor : cursor+digestLength]
	return Payload{
		KeyID:         base64.RawURLEncoding.EncodeToString(kidRaw),
		TicketID:      ticketID,
		TripID:        tripID,
		Seat:          seat,
		IssuedAt:      time.Unix(issuedAt, 0).UTC(),
		ExpiresAt:     time.Unix(expiresAt, 0).UTC(),
		RotationEpoch: epoch,
		HolderDigest:  hex.EncodeToString(holder),
	}, payloadBytes, signature, windowCode, nil
}

// keyID derives the raw 8-byte kid of a public key.
func keyID(public ed25519.PublicKey) []byte {
	digest := sha256.Sum256(public)
	return digest[:kidLength]
}

// RotatedKey is the immediately previous signing key, accepted until
// GraceUntil (mirrors the maritime feed key-rotation grace pattern).
type RotatedKey struct {
	Public     ed25519.PublicKey
	Epoch      uint32
	GraceUntil time.Time
}

// KeySet holds the active signing key and the optional previous key inside
// its grace window. Constructed from env-injected key material; there are no
// defaults and no placeholder keys.
type KeySet struct {
	current ed25519.PrivateKey
	epoch   uint32
	// previous kid -> rotated key (a single prior epoch is supported,
	// matching the feed rotation pattern)
	previous *RotatedKey
}

// NewKeySet fails closed on any malformed key material.
func NewKeySet(current ed25519.PrivateKey, rotationEpoch uint32, previous *RotatedKey) (*KeySet, error) {
	if len(current) != ed25519.PrivateKeySize {
		return nil, errors.New("current ed25519 private key is required (fail-closed)")
	}
	if rotationEpoch == 0 {
		return nil, errors.New("rotation epoch must be at least 1")
	}
	set := &KeySet{current: current, epoch: rotationEpoch}
	if previous != nil {
		if len(previous.Public) != ed25519.PublicKeySize {
			return nil, errors.New("previous ed25519 public key is required when rotation is configured")
		}
		if previous.GraceUntil.IsZero() {
			return nil, errors.New("previous key grace deadline is required when rotation is configured")
		}
		if previous.Epoch == 0 || previous.Epoch >= rotationEpoch {
			return nil, errors.New("previous key epoch must be positive and below the current epoch")
		}
		copy := *previous
		set.previous = &copy
	}
	return set, nil
}

// CurrentKeyID returns the kid of the active signing key (base64url).
func (set *KeySet) CurrentKeyID() string {
	return base64.RawURLEncoding.EncodeToString(keyID(set.current.Public().(ed25519.PublicKey)))
}

// VerificationKey is the public, distributable view of one trusted key:
// everything an offline verifier needs to pin the key (kid, raw public key,
// epoch, grace deadline), and nothing secret — private key material and the
// HMAC window secret are never part of this view.
type VerificationKey struct {
	KeyID      string // base64url kid, SHA-256(public key)[0:8]
	Public     ed25519.PublicKey
	Epoch      uint32
	GraceUntil time.Time // zero for the current key
}

// VerificationKeys exposes the current and (when configured) previous public
// keys for distribution to offline verifiers (gate scanners, the mobile
// inspector). The previous key is reported regardless of its grace deadline;
// consumers decide trust at their own clock.
func (set *KeySet) VerificationKeys() (current VerificationKey, previous *VerificationKey) {
	public := set.current.Public().(ed25519.PublicKey)
	current = VerificationKey{
		KeyID:  base64.RawURLEncoding.EncodeToString(keyID(public)),
		Public: append(ed25519.PublicKey(nil), public...),
		Epoch:  set.epoch,
	}
	if set.previous != nil {
		previous = &VerificationKey{
			KeyID:      base64.RawURLEncoding.EncodeToString(keyID(set.previous.Public)),
			Public:     append(ed25519.PublicKey(nil), set.previous.Public...),
			Epoch:      set.previous.Epoch,
			GraceUntil: set.previous.GraceUntil,
		}
	}
	return current, previous
}

// RotationEpoch returns the active signing epoch.
func (set *KeySet) RotationEpoch() uint32 { return set.epoch }

// Sign renders the canonical payload, signs it with the current key and
// appends the rotating window code valid at `at`.
func (set *KeySet) Sign(payload Payload, serverWindowSecret string, at time.Time) (string, error) {
	if len(serverWindowSecret) < 16 {
		return "", errors.New("server window secret of at least 16 characters is required (fail-closed)")
	}
	public := set.current.Public().(ed25519.PublicKey)
	payload.RotationEpoch = set.epoch
	canonical, err := payload.marshal(keyID(public))
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(set.current, canonical)
	artifact := make([]byte, 0, len(canonical)+signatureLength+windowCodeLength)
	artifact = append(artifact, canonical...)
	artifact = append(artifact, signature...)
	artifact = append(artifact, WindowCode(serverWindowSecret, payload.TicketID, at)...)
	return base64.RawURLEncoding.EncodeToString(artifact), nil
}

// Verifier exposes public-key-only verification for offline consumers
// (gate scanners, the future mobile app). It never requires network or DB
// access for authenticity.
func (set *KeySet) Verifier(serverWindowSecret string) (*Verifier, error) {
	verifier := &Verifier{
		current:      set.current.Public().(ed25519.PublicKey),
		currentEpoch: set.epoch,
		windowSecret: serverWindowSecret,
	}
	if set.previous != nil {
		copy := *set.previous
		verifier.previous = &copy
	}
	return verifier, nil
}

// Verifier verifies artifacts against the trusted public key set. With a
// window secret configured it also enforces the rotating code; without one it
// performs authenticity-only checks (the mobile-app embedding).
type Verifier struct {
	current      ed25519.PublicKey
	currentEpoch uint32
	previous     *RotatedKey
	windowSecret string
}

// NewPublicVerifier builds an authenticity-only verifier from public keys —
// exactly what an offline gate or mobile client embeds.
func NewPublicVerifier(current ed25519.PublicKey, currentEpoch uint32, previous *RotatedKey) (*Verifier, error) {
	if len(current) != ed25519.PublicKeySize {
		return nil, errors.New("current ed25519 public key is required (fail-closed)")
	}
	if currentEpoch == 0 {
		return nil, errors.New("rotation epoch must be at least 1")
	}
	verifier := &Verifier{current: current, currentEpoch: currentEpoch}
	if previous != nil {
		if len(previous.Public) != ed25519.PublicKeySize || previous.GraceUntil.IsZero() || previous.Epoch == 0 || previous.Epoch >= currentEpoch {
			return nil, errors.New("previous key requires a public key, a grace deadline and a lower positive epoch")
		}
		copy := *previous
		verifier.previous = &copy
	}
	return verifier, nil
}

// WindowSecret exposes the configured server window secret (empty on
// authenticity-only verifiers).
func (verifier *Verifier) WindowSecret() string { return verifier.windowSecret }

// VerifyAuthenticity decodes the token, resolves the kid against the trusted
// set (current key always, previous key inside its grace window) and verifies
// the Ed25519 signature and expiry. No window-code check: this is the check
// an offline mobile client can perform.
func (verifier *Verifier) VerifyAuthenticity(token string, now time.Time) (Payload, error) {
	payload, payloadBytes, signature, _, err := verifier.decode(token)
	if err != nil {
		return Payload{}, err
	}
	if err := verifier.verifySignature(payload, payloadBytes, signature, now); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

// Verify performs authenticity plus the rotating window code check. It fails
// closed when the verifier has no window secret configured.
func (verifier *Verifier) Verify(token string, now time.Time) (Payload, error) {
	if len(verifier.windowSecret) < 16 {
		return Payload{}, errors.New("server window secret is required for full verification (fail-closed)")
	}
	payload, payloadBytes, signature, windowCode, err := verifier.decode(token)
	if err != nil {
		return Payload{}, err
	}
	if err := verifier.verifySignature(payload, payloadBytes, signature, now); err != nil {
		return Payload{}, err
	}
	if !verifyWindowCode(verifier.windowSecret, payload.TicketID, windowCode, now) {
		return Payload{}, ErrWindowCodeInvalid
	}
	return payload, nil
}

func (verifier *Verifier) decode(token string) (Payload, []byte, []byte, []byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return Payload{}, nil, nil, nil, ErrMalformedArtifact
	}
	return parsePayload(raw)
}

func (verifier *Verifier) verifySignature(payload Payload, payloadBytes, signature []byte, now time.Time) error {
	kidRaw, err := base64.RawURLEncoding.DecodeString(payload.KeyID)
	if err != nil || len(kidRaw) != kidLength {
		return ErrMalformedArtifact
	}
	key, epoch, err := verifier.trustedKey(kidRaw, now)
	if err != nil {
		return err
	}
	if payload.RotationEpoch != epoch {
		return ErrUnknownKeyID
	}
	if !ed25519.Verify(key, payloadBytes, signature) {
		return ErrInvalidSignature
	}
	if !now.Before(payload.ExpiresAt) {
		return ErrArtifactExpired
	}
	return nil
}

// trustedKey resolves a raw kid to the trusted public key and its epoch.
func (verifier *Verifier) trustedKey(kidRaw []byte, now time.Time) (ed25519.PublicKey, uint32, error) {
	if bytes.Equal(kidRaw, keyID(verifier.current)) {
		return verifier.current, verifier.currentEpoch, nil
	}
	if verifier.previous != nil && bytes.Equal(kidRaw, keyID(verifier.previous.Public)) {
		if !now.Before(verifier.previous.GraceUntil) {
			return nil, 0, ErrRotationGraceExpired
		}
		return verifier.previous.Public, verifier.previous.Epoch, nil
	}
	return nil, 0, ErrUnknownKeyID
}

// WindowCode derives the rotating code for one ticket at one instant.
func WindowCode(serverWindowSecret, ticketID string, at time.Time) []byte {
	return windowCodeAt(serverWindowSecret, ticketID, at.Unix()/WindowStepSeconds)
}

func windowCodeAt(serverWindowSecret, ticketID string, window int64) []byte {
	mac := hmac.New(sha256.New, []byte(serverWindowSecret))
	mac.Write([]byte("BET1-window"))
	mac.Write([]byte(ticketID))
	secret := mac.Sum(nil)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(window))
	code := hmac.New(sha256.New, secret)
	code.Write(counter[:])
	return code.Sum(nil)[:windowCodeLength]
}

// verifyWindowCode accepts the current window plus/minus the tolerance.
func verifyWindowCode(serverWindowSecret, ticketID string, presented []byte, now time.Time) bool {
	if len(presented) != windowCodeLength {
		return false
	}
	current := now.Unix() / WindowStepSeconds
	for offset := int64(-WindowTolerance); offset <= WindowTolerance; offset++ {
		if hmac.Equal(presented, windowCodeAt(serverWindowSecret, ticketID, current+offset)) {
			return true
		}
	}
	return false
}

// LoadPrivateKeyFile reads an env-injected Ed25519 private key file. The file
// holds the 64-byte private key (or 32-byte seed) encoded as hex or base64
// (standard, URL-safe, padded or raw). It fails closed on anything else and
// never fabricates key material.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("signing key file path is required (fail-closed)")
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read signing key file: %w", err)
	}
	text := strings.TrimSpace(string(raw))
	for _, decode := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		decoded, decodeErr := decode(text)
		if decodeErr != nil {
			continue
		}
		switch len(decoded) {
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(decoded), nil
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(decoded), nil
		}
	}
	return nil, fmt.Errorf("signing key file %s does not contain a hex/base64 ed25519 key or seed", path)
}
