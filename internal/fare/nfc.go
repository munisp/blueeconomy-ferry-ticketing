package fare

// nfc.go — PRA-133: NFC tap payload model and verification (server side).
//
// The tap is an NDEF/EMV-style binary TLV record signed by the enrolled
// instrument key (Ed25519), so a conductor/validator device can verify it
// OFFLINE against the synced enrollment key and the server re-verifies the
// same bytes on batch upload. Anti-replay is the monotonic tap counter: the
// server spends counters (instruments.tap_counter), so a cloned payload
// with a consumed counter is denied.
//
// HONEST CONSTRAINT (registered): mobile NFC hardware APIs cannot be
// exercised in this environment. This file implements the server-side parse
// + verify + counter semantics only; tests use real TLV fixtures built with
// EncodeTapPayload. No hardware behavior is fabricated.
//
// Wire layout (tag u8, length u8, value):
//
//	0x01  envelope version, ASCII "1.0"            (envelope v1.0 contract)
//	0x02  instrument token reference, UTF-8
//	0x03  amount, NGN minor units, u64 big-endian
//	0x04  tap counter, u64 big-endian (monotonic per instrument)
//	0x05  tapped-at, unix seconds, u64 big-endian
//	0x06  Ed25519 signature (64B) over the canonical TLV of tags 01..05
//
// Fail-closed parsing: duplicate tags, unknown tags, trailing bytes, bad
// lengths and malformed integers are all rejected.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	tapTagVersion   = 0x01
	tapTagTokenRef  = 0x02
	tapTagAmount    = 0x03
	tapTagCounter   = 0x04
	tapTagTappedAt  = 0x05
	tapTagSignature = 0x06

	// TapEnvelopeVersion is the signed-artifact envelope contract (v1.0).
	TapEnvelopeVersion = "1.0"
)

// TapPayload is one parsed NFC tap.
type TapPayload struct {
	TokenRef    string
	AmountMinor int64
	Counter     uint64
	TappedAt    time.Time
	Signature   []byte
}

// encodeTLVField renders one binary TLV field.
func encodeTLVField(tag byte, value []byte) []byte {
	if len(value) > 255 {
		panic("TLV value too long")
	}
	return append([]byte{tag, byte(len(value))}, value...)
}

// canonicalTapBytes renders tags 01..05 in tag order — the signed bytes.
func canonicalTapBytes(payload TapPayload) []byte {
	out := encodeTLVField(tapTagVersion, []byte(TapEnvelopeVersion))
	out = append(out, encodeTLVField(tapTagTokenRef, []byte(payload.TokenRef))...)
	var amount, counter, tappedAt [8]byte
	binary.BigEndian.PutUint64(amount[:], uint64(payload.AmountMinor))
	binary.BigEndian.PutUint64(counter[:], payload.Counter)
	binary.BigEndian.PutUint64(tappedAt[:], uint64(payload.TappedAt.Unix()))
	out = append(out, encodeTLVField(tapTagAmount, amount[:])...)
	out = append(out, encodeTLVField(tapTagCounter, counter[:])...)
	out = append(out, encodeTLVField(tapTagTappedAt, tappedAt[:])...)
	return out
}

// EncodeTapPayload signs one tap with the instrument private key and renders
// the base64url transport form. Used by enrollment-side tooling and by the
// test fixtures (the hardware path produces the identical wire format).
func EncodeTapPayload(privateKey ed25519.PrivateKey, tokenRef string, amountMinor int64, counter uint64, tappedAt time.Time) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("instrument private key is required")
	}
	if strings.TrimSpace(tokenRef) == "" || len(tokenRef) > 250 {
		return "", errors.New("token reference is required")
	}
	if amountMinor <= 0 {
		return "", errors.New("amount must be positive")
	}
	payload := TapPayload{TokenRef: tokenRef, AmountMinor: amountMinor, Counter: counter, TappedAt: tappedAt.UTC()}
	signed := canonicalTapBytes(payload)
	payload.Signature = ed25519.Sign(privateKey, signed)
	wire := append(signed, encodeTLVField(tapTagSignature, payload.Signature)...)
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

// parseTapTLV decodes the wire form into a tag map, failing closed on any
// structural anomaly.
func parseTapTLV(wire []byte) (map[byte][]byte, error) {
	fields := map[byte][]byte{}
	for offset := 0; offset < len(wire); {
		if offset+2 > len(wire) {
			return nil, errors.New("truncated TLV header")
		}
		tag, length := wire[offset], int(wire[offset+1])
		offset += 2
		if offset+length > len(wire) {
			return nil, fmt.Errorf("truncated TLV value for tag %02x", tag)
		}
		if _, duplicate := fields[tag]; duplicate {
			return nil, fmt.Errorf("duplicate TLV tag %02x", tag)
		}
		switch tag {
		case tapTagVersion, tapTagTokenRef, tapTagAmount, tapTagCounter, tapTagTappedAt, tapTagSignature:
		default:
			return nil, fmt.Errorf("unknown TLV tag %02x", tag)
		}
		fields[tag] = wire[offset : offset+length]
		offset += length
	}
	return fields, nil
}

// ParseTapPayload decodes and structurally validates one base64url tap.
func ParseTapPayload(artifact string) (TapPayload, error) {
	wire, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(artifact))
	if err != nil {
		return TapPayload{}, fmt.Errorf("tap artifact is not base64url: %w", err)
	}
	fields, err := parseTapTLV(wire)
	if err != nil {
		return TapPayload{}, err
	}
	if string(fields[tapTagVersion]) != TapEnvelopeVersion {
		return TapPayload{}, errors.New("tap envelope version is not 1.0")
	}
	if len(fields[tapTagAmount]) != 8 || len(fields[tapTagCounter]) != 8 || len(fields[tapTagTappedAt]) != 8 {
		return TapPayload{}, errors.New("tap numeric fields must be 8 bytes")
	}
	if len(fields[tapTagSignature]) != ed25519.SignatureSize {
		return TapPayload{}, errors.New("tap signature must be 64 bytes")
	}
	payload := TapPayload{
		TokenRef:    string(fields[tapTagTokenRef]),
		AmountMinor: int64(binary.BigEndian.Uint64(fields[tapTagAmount])),
		Counter:     binary.BigEndian.Uint64(fields[tapTagCounter]),
		TappedAt:    time.Unix(int64(binary.BigEndian.Uint64(fields[tapTagTappedAt])), 0).UTC(),
		Signature:   fields[tapTagSignature],
	}
	if payload.TokenRef == "" || payload.AmountMinor <= 0 {
		return TapPayload{}, errors.New("tap token reference and positive amount are required")
	}
	return payload, nil
}

// VerifyTapSignature checks the instrument signature over the canonical
// bytes (offline-capable: the device needs only the enrolled public key).
func VerifyTapSignature(publicKeyHex string, payload TapPayload) error {
	publicKey, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("instrument public key is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonicalTapBytes(payload), payload.Signature) {
		return errors.New("tap signature is invalid")
	}
	return nil
}
