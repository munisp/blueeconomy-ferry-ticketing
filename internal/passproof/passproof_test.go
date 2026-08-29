package passproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDigest() string {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	return hex.EncodeToString(digest)
}

func validPayload(passID string) Payload {
	return Payload{
		PassID:       passID,
		ProductID:    "product-week-network",
		ScopeType:    ScopeNetwork,
		ValidFrom:    time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ValidTo:      time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second),
		HolderDigest: mustDigest(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := mustKey(t)
	signer, err := NewSigner(key, 3)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(validPayload("pass-1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier([]TrustedKey{{KeyID: KeyIDString(signer.Public()), Public: signer.Public(), Epoch: 3}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if payload.PassID != "pass-1" || payload.KeyEpoch != 3 || payload.ScopeType != ScopeNetwork {
		t.Fatalf("payload mismatch: %+v", payload)
	}
}

func TestVerifyRejectsWrongEpochAndTampering(t *testing.T) {
	current := mustKey(t)
	next := mustKey(t)
	signer, _ := NewSigner(next, 2)
	token, err := signer.Sign(validPayload("pass-epoch"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Directory only knows epoch 1: an artifact from epoch 2 must reject.
	verifier, err := NewVerifier([]TrustedKey{{KeyID: KeyIDString(current.Public().(ed25519.PublicKey)), Public: current.Public().(ed25519.PublicKey), Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("wrong epoch must reject with ErrUnknownKeyID, got %v", err)
	}
	// Tampered signature rejects.
	raw := []byte(token)
	raw[len(raw)-3] ^= 0xFF
	if _, err := verifier.Verify(string(raw)); err == nil {
		t.Fatal("tampered token must reject")
	}
	if _, err := verifier.Verify("!!!not-base64!!!"); !errors.Is(err, ErrMalformedArtifact) {
		t.Fatalf("malformed token must reject with ErrMalformedArtifact, got %v", err)
	}
}

func TestVerifierFailsClosedWithoutKeys(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("empty trusted key set must fail closed")
	}
}

func TestBlocklistSignAndVerify(t *testing.T) {
	key := mustKey(t)
	signer, _ := NewSigner(key, 1)
	since := int64(1725000000)
	passIDs := []string{"pass-a", "pass-b", "pass-c"}
	signature, err := signer.SignBlocklist(since, passIDs)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier([]TrustedKey{{KeyID: KeyIDString(signer.Public()), Public: signer.Public(), Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyBlocklist(1, since, passIDs, signature); err != nil {
		t.Fatalf("blocklist verify: %v", err)
	}
	// A mutated page rejects.
	if err := verifier.VerifyBlocklist(1, since, []string{"pass-a", "pass-x"}, signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("mutated blocklist page must reject, got %v", err)
	}
	// A page signed at the wrong epoch rejects.
	if err := verifier.VerifyBlocklist(2, since, passIDs, signature); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("wrong-epoch blocklist page must reject, got %v", err)
	}
}

func TestScopeCodeFailsClosed(t *testing.T) {
	if _, err := ScopeCode("CITYWIDE"); err == nil {
		t.Fatal("unknown scope must fail closed")
	}
}
