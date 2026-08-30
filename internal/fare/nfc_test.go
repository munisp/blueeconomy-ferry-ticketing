package fare

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// PRA-133 unit tests: real TLV fixtures (no hardware — wire format only).

func tapKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestTapPayloadRoundTrip(t *testing.T) {
	publicKey, privateKey := tapKeyPair(t)
	tappedAt := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	artifact, err := EncodeTapPayload(privateKey, "tap-token-1", 25000, 7, tappedAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ParseTapPayload(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if payload.TokenRef != "tap-token-1" || payload.AmountMinor != 25000 || payload.Counter != 7 ||
		!payload.TappedAt.Equal(tappedAt) {
		t.Fatalf("payload = %+v", payload)
	}
	if err := VerifyTapSignature(hex.EncodeToString(publicKey), payload); err != nil {
		t.Fatalf("signature must verify: %v", err)
	}
}

func TestTapPayloadFailClosed(t *testing.T) {
	publicKey, privateKey := tapKeyPair(t)
	tappedAt := time.Now().UTC()
	good, err := EncodeTapPayload(privateKey, "tap-token-1", 1000, 1, tappedAt)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(publicKey)

	// Not base64.
	if _, err := ParseTapPayload("!!!not-base64!!!"); err == nil {
		t.Fatal("malformed base64 must reject")
	}
	// Truncated wire.
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	if _, err := ParseTapPayload(base64.RawURLEncoding.EncodeToString(raw[:len(raw)-10])); err == nil {
		t.Fatal("truncated TLV must reject")
	}
	// Unknown tag.
	raw2 := append(append([]byte{}, raw...), 0x7F, 0x01, 0x00)
	if _, err := ParseTapPayload(base64.RawURLEncoding.EncodeToString(raw2)); err == nil {
		t.Fatal("unknown tag must reject")
	}
	// Tampered amount (flip a byte inside the amount field): signature fails.
	payload, err := ParseTapPayload(good)
	if err != nil {
		t.Fatal(err)
	}
	payload.AmountMinor = 9999
	if err := VerifyTapSignature(keyHex, payload); err == nil {
		t.Fatal("tampered amount must fail verification")
	}
	// Wrong key.
	otherPublic, _ := tapKeyPair(t)
	payload, _ = ParseTapPayload(good)
	if err := VerifyTapSignature(hex.EncodeToString(otherPublic), payload); err == nil {
		t.Fatal("wrong key must fail verification")
	}
	// Malformed key material.
	if err := VerifyTapSignature("deadbeef", payload); err == nil {
		t.Fatal("malformed key must fail verification")
	}
}

func TestTapPayloadDuplicateTagRejected(t *testing.T) {
	_, privateKey := tapKeyPair(t)
	good, err := EncodeTapPayload(privateKey, "tap-token-1", 1000, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	// Append a second version tag: duplicate rejection.
	dupe := append(append([]byte{}, raw...), encodeTLVField(tapTagVersion, []byte("1.0"))...)
	if _, err := ParseTapPayload(base64.RawURLEncoding.EncodeToString(dupe)); !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate tag must reject, got %v", err)
	}
}
