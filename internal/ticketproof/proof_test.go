package ticketproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testWindowSecret = "test-window-secret-0123456789"

var testNow = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func generateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key
}

func testPayload() Payload {
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = byte(index)
	}
	return Payload{
		TicketID:     "ticket-abc-123",
		TripID:       "trip-xyz-789",
		Seat:         42,
		IssuedAt:     testNow.Add(-time.Hour),
		ExpiresAt:    testNow.Add(2 * time.Hour),
		HolderDigest: hex.EncodeToString(digest),
	}
}

func newTestKeySet(t *testing.T) (*KeySet, ed25519.PrivateKey) {
	t.Helper()
	key := generateKey(t)
	set, err := NewKeySet(key, 1, nil)
	require.NoError(t, err)
	return set, key
}

func TestSignVerifyRoundTrip(t *testing.T) {
	set, key := newTestKeySet(t)
	token, err := set.Sign(testPayload(), testWindowSecret, testNow)
	require.NoError(t, err)

	verifier, err := set.Verifier(testWindowSecret)
	require.NoError(t, err)
	payload, err := verifier.Verify(token, testNow)
	require.NoError(t, err)
	require.Equal(t, "ticket-abc-123", payload.TicketID)
	require.Equal(t, "trip-xyz-789", payload.TripID)
	require.Equal(t, 42, payload.Seat)
	require.Equal(t, testPayload().HolderDigest, payload.HolderDigest)
	require.Equal(t, uint32(1), payload.RotationEpoch)
	require.Equal(t, testNow.Add(-time.Hour).Unix(), payload.IssuedAt.Unix())
	require.Equal(t, set.CurrentKeyID(), payload.KeyID)

	// Authenticity-only verification (the mobile embedding) needs no window
	// secret and accepts the same token.
	publicOnly, err := NewPublicVerifier(key.Public().(ed25519.PublicKey), 1, nil)
	require.NoError(t, err)
	_, err = publicOnly.VerifyAuthenticity(token, testNow)
	require.NoError(t, err)
	// ...but full verification without the window secret fails closed.
	_, err = publicOnly.Verify(token, testNow)
	require.Error(t, err)
}

func TestTamperRejection(t *testing.T) {
	set, _ := newTestKeySet(t)
	token, err := set.Sign(testPayload(), testWindowSecret, testNow)
	require.NoError(t, err)
	verifier, err := set.Verifier(testWindowSecret)
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)

	// Flip one byte inside the signed ticket_id: signature must fail.
	tampered := append([]byte(nil), raw...)
	tampered[14] ^= 0xFF
	_, err = verifier.Verify(base64.RawURLEncoding.EncodeToString(tampered), testNow)
	require.ErrorIs(t, err, ErrInvalidSignature)

	// Flip one byte in the signature itself.
	tampered = append([]byte(nil), raw...)
	tampered[len(raw)-9] ^= 0x01
	_, err = verifier.Verify(base64.RawURLEncoding.EncodeToString(tampered), testNow)
	require.ErrorIs(t, err, ErrInvalidSignature)

	// Flip one byte in the trailing window code: window check must fail.
	tampered = append([]byte(nil), raw...)
	tampered[len(raw)-1] ^= 0x01
	_, err = verifier.Verify(base64.RawURLEncoding.EncodeToString(tampered), testNow)
	require.ErrorIs(t, err, ErrWindowCodeInvalid)

	// Truncated and garbage tokens are malformed, never panics.
	_, err = verifier.Verify(base64.RawURLEncoding.EncodeToString(raw[:20]), testNow)
	require.ErrorIs(t, err, ErrMalformedArtifact)
	_, err = verifier.Verify("!!!not-base64!!!", testNow)
	require.ErrorIs(t, err, ErrMalformedArtifact)
	_, err = verifier.Verify("", testNow)
	require.ErrorIs(t, err, ErrMalformedArtifact)
}

func TestWrongKeyAndUnknownKidRejection(t *testing.T) {
	set, _ := newTestKeySet(t)
	token, err := set.Sign(testPayload(), testWindowSecret, testNow)
	require.NoError(t, err)

	// A verifier trusting a different key rejects both the kid and (with a
	// forged kid) the signature.
	other := generateKey(t)
	stranger, err := NewPublicVerifier(other.Public().(ed25519.PublicKey), 1, nil)
	require.NoError(t, err)
	_, err = stranger.VerifyAuthenticity(token, testNow)
	require.ErrorIs(t, err, ErrUnknownKeyID)
	require.Equal(t, "unknown_kid", FailureReason(err))
}

func TestKeyRotationGraceWindow(t *testing.T) {
	previousKey := generateKey(t)
	currentKey := generateKey(t)
	graceUntil := testNow.Add(time.Hour)

	// Artifacts signed before rotation used the previous key at epoch 1.
	oldSet, err := NewKeySet(previousKey, 1, nil)
	require.NoError(t, err)
	token, err := oldSet.Sign(testPayload(), testWindowSecret, testNow)
	require.NoError(t, err)

	// After rotation the verifier trusts current (epoch 2) plus the previous
	// key inside its grace window.
	rotated := &RotatedKey{Public: previousKey.Public().(ed25519.PublicKey), Epoch: 1, GraceUntil: graceUntil}
	verifier, err := NewPublicVerifier(currentKey.Public().(ed25519.PublicKey), 2, rotated)
	require.NoError(t, err)
	verifier.windowSecret = testWindowSecret

	// Inside the grace window: accepted.
	payload, err := verifier.Verify(token, testNow)
	require.NoError(t, err)
	require.Equal(t, uint32(1), payload.RotationEpoch)

	// Grace boundaries are authenticity checks (the rotating code has long
	// expired by the grace deadline; presenters re-mint artifacts).
	_, err = verifier.VerifyAuthenticity(token, graceUntil.Add(-time.Second))
	require.NoError(t, err, "one second before the grace deadline: still accepted")

	// At/after the grace deadline: rejected as expired rotation.
	_, err = verifier.VerifyAuthenticity(token, graceUntil)
	require.ErrorIs(t, err, ErrRotationGraceExpired)
	require.Equal(t, "rotation_grace_expired", FailureReason(err))
	_, err = verifier.VerifyAuthenticity(token, graceUntil.Add(time.Minute))
	require.ErrorIs(t, err, ErrRotationGraceExpired)

	// A forged epoch on a previous-kid artifact is rejected as unknown.
	forged := testPayload()
	forgedSet, err := NewKeySet(previousKey, 2, nil)
	require.NoError(t, err)
	forgedToken, err := forgedSet.Sign(forged, testWindowSecret, testNow)
	require.NoError(t, err)
	_, err = verifier.Verify(forgedToken, testNow)
	require.ErrorIs(t, err, ErrUnknownKeyID)

	// New artifacts signed with the current key verify at epoch 2.
	newSet, err := NewKeySet(currentKey, 2, rotated)
	require.NoError(t, err)
	newToken, err := newSet.Sign(testPayload(), testWindowSecret, testNow)
	require.NoError(t, err)
	payload, err = verifier.Verify(newToken, testNow)
	require.NoError(t, err)
	require.Equal(t, uint32(2), payload.RotationEpoch)
}

func TestWindowCodeBoundaries(t *testing.T) {
	set, _ := newTestKeySet(t)
	verifier, err := set.Verifier(testWindowSecret)
	require.NoError(t, err)

	// Align to a window boundary so offsets are exact.
	windowStart := time.Unix(testNow.Unix()-testNow.Unix()%WindowStepSeconds, 0).UTC()
	token, err := set.Sign(testPayload(), testWindowSecret, windowStart)
	require.NoError(t, err)

	// Current window and +/-1 window are accepted.
	for _, delta := range []time.Duration{-30 * time.Second, 0, 29 * time.Second, 30 * time.Second} {
		_, err := verifier.Verify(token, windowStart.Add(delta))
		require.NoError(t, err, "delta %s", delta)
	}
	// +/-2 windows are outside tolerance: the static screenshot has expired.
	_, err = verifier.Verify(token, windowStart.Add(-31*time.Second))
	require.ErrorIs(t, err, ErrWindowCodeInvalid)
	_, err = verifier.Verify(token, windowStart.Add(61*time.Second))
	require.ErrorIs(t, err, ErrWindowCodeInvalid)
	require.Equal(t, "window_code_invalid", FailureReason(err))

	// A code minted for a different ticket never validates.
	other := testPayload()
	other.TicketID = "ticket-other"
	otherToken, err := set.Sign(other, testWindowSecret, windowStart)
	require.NoError(t, err)
	_, err = verifier.Verify(otherToken, windowStart)
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(otherToken)
	require.NoError(t, err)
	// Swap in the window code of the first ticket: fails.
	originalRaw, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	copy(raw[len(raw)-8:], originalRaw[len(originalRaw)-8:])
	_, err = verifier.Verify(base64.RawURLEncoding.EncodeToString(raw), windowStart)
	require.ErrorIs(t, err, ErrWindowCodeInvalid)
}

func TestArtifactExpiry(t *testing.T) {
	set, _ := newTestKeySet(t)
	verifier, err := set.Verifier(testWindowSecret)
	require.NoError(t, err)
	// The window code can be recomputed by the presenter; expiry is checked
	// against the signed expires_at regardless.
	expired := testNow.Add(2*time.Hour + time.Second)
	fresh, err := set.Sign(testPayload(), testWindowSecret, expired)
	require.NoError(t, err)
	_, err = verifier.Verify(fresh, expired)
	require.ErrorIs(t, err, ErrArtifactExpired)
	require.Equal(t, "artifact_expired", FailureReason(err))
}

func TestFailClosedConstruction(t *testing.T) {
	_, err := NewKeySet(nil, 1, nil)
	require.Error(t, err)
	_, err = NewKeySet(generateKey(t), 0, nil)
	require.Error(t, err)
	_, err = NewKeySet(generateKey(t), 1, &RotatedKey{Public: nil, Epoch: 1, GraceUntil: testNow})
	require.Error(t, err)
	_, err = NewKeySet(generateKey(t), 1, &RotatedKey{Public: generateKey(t).Public().(ed25519.PublicKey), Epoch: 1, GraceUntil: time.Time{}})
	require.Error(t, err)
	// Previous epoch must be below current.
	_, err = NewKeySet(generateKey(t), 1, &RotatedKey{Public: generateKey(t).Public().(ed25519.PublicKey), Epoch: 1, GraceUntil: testNow})
	require.Error(t, err)
	_, err = NewPublicVerifier(nil, 1, nil)
	require.Error(t, err)
	// Signing requires the window secret.
	set, _ := newTestKeySet(t)
	_, err = set.Sign(testPayload(), "", testNow)
	require.Error(t, err)
	_, err = set.Sign(testPayload(), "short", testNow)
	require.Error(t, err)
	// Holder digest must be a real SHA-256 hex digest.
	bad := testPayload()
	bad.HolderDigest = "not-hex"
	_, err = set.Sign(bad, testWindowSecret, testNow)
	require.Error(t, err)
}

func TestLoadPrivateKeyFile(t *testing.T) {
	key := generateKey(t)
	dir := t.TempDir()

	byHex := filepath.Join(dir, "key.hex")
	require.NoError(t, os.WriteFile(byHex, []byte(hex.EncodeToString(key)+"\n"), 0o600))
	loaded, err := LoadPrivateKeyFile(byHex)
	require.NoError(t, err)
	require.Equal(t, key, loaded)

	byBase64 := filepath.Join(dir, "key.b64")
	require.NoError(t, os.WriteFile(byBase64, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600))
	loaded, err = LoadPrivateKeyFile(byBase64)
	require.NoError(t, err)
	require.Equal(t, key, loaded)

	seed := filepath.Join(dir, "seed.hex")
	require.NoError(t, os.WriteFile(seed, []byte(hex.EncodeToString(key.Seed())), 0o600))
	loaded, err = LoadPrivateKeyFile(seed)
	require.NoError(t, err)
	require.Equal(t, key, loaded)

	// Fail closed: missing path, missing file, garbage content.
	_, err = LoadPrivateKeyFile("")
	require.Error(t, err)
	_, err = LoadPrivateKeyFile(filepath.Join(dir, "absent"))
	require.Error(t, err)
	garbage := filepath.Join(dir, "garbage")
	require.NoError(t, os.WriteFile(garbage, []byte("not a key at all !!!"), 0o600))
	_, err = LoadPrivateKeyFile(garbage)
	require.Error(t, err)
}
