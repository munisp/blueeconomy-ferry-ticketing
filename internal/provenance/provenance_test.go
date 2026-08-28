package provenance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSigner(t *testing.T, kid string) *Signer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = public
	signer, err := NewSigner(kid, private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func directoryWith(t *testing.T, signers ...*Signer) *Directory {
	t.Helper()
	entries := make(map[string]string, len(signers))
	for _, signer := range signers {
		entries[signer.KeyID()] = signer.PublicKey()
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := ParseDirectory(raw)
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

type testEnvelope struct {
	EnvelopeVersion string `json:"envelopeVersion"`
	EventID         string `json:"eventId"`
	Producer        string `json:"producer"`
	Provenance      struct {
		PrincipalID string `json:"principalId"`
		Signature   string `json:"signature"`
	} `json:"provenance"`
	Classification string `json:"classification"`
}

func signedTestEnvelope(t *testing.T, signer *Signer) []byte {
	t.Helper()
	envelope := testEnvelope{EnvelopeVersion: "1.0", EventID: "evt-1", Producer: "unit-test", Classification: "INTERNAL"}
	envelope.Provenance.PrincipalID = "principal-1"
	signature, err := signer.SignEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Provenance.Signature = signature
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	directory := directoryWith(t, signer)
	raw := signedTestEnvelope(t, signer)
	if err := directory.VerifyEnvelope(raw); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	directory := directoryWith(t, signer)
	raw := signedTestEnvelope(t, signer)

	tampered := strings.Replace(string(raw), `"evt-1"`, `"evt-2"`, 1)
	if tampered == string(raw) {
		t.Fatal("fixture did not contain eventId")
	}
	if err := directory.VerifyEnvelope([]byte(tampered)); err == nil {
		t.Fatal("tampered envelope verified")
	}

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["classification"] = "PUBLIC"
	resealed, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.VerifyEnvelope(resealed); err == nil {
		t.Fatal("reordered tampered envelope verified")
	}
}

func TestUnknownKidRejected(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	other := testSigner(t, "other-producer-1")
	directory := directoryWith(t, other)
	raw := signedTestEnvelope(t, signer)
	err := directory.VerifyEnvelope(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown provenance key id") {
		t.Fatalf("expected unknown kid rejection, got %v", err)
	}
}

func TestMalformedJWSRejected(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	directory := directoryWith(t, signer)
	raw := signedTestEnvelope(t, signer)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	provenance := document["provenance"].(map[string]any)
	for _, forged := range []string{"not-a-jws", "a.b", "a.b.c", "..", "a.b.c.d"} {
		provenance["signature"] = forged
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if verifyErr := directory.VerifyEnvelope(encoded); verifyErr == nil {
			t.Fatalf("malformed JWS %q verified", forged)
		}
	}
	provenance["signature"] = ""
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if verifyErr := directory.VerifyEnvelope(encoded); verifyErr == nil {
		t.Fatal("empty signature verified")
	}
}

func TestWrongAlgorithmRejected(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	directory := directoryWith(t, signer)
	raw := signedTestEnvelope(t, signer)
	payload, signature, err := SignedPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = payload
	jwsParts := strings.Split(signature, ".")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"unit-test-1"}`))
	forged := header + "." + jwsParts[1] + "." + jwsParts[2]
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["provenance"].(map[string]any)["signature"] = forged
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if verifyErr := directory.VerifyEnvelope(encoded); verifyErr == nil {
		t.Fatal("non-EdDSA JWS verified")
	}
}

func TestStartupRefusalWithoutKey(t *testing.T) {
	t.Setenv(EnvSigningKey, "")
	if _, err := LoadSignerFromEnv("unit-test-1"); err == nil {
		t.Fatal("signer loaded without a key")
	}
	t.Setenv(EnvSigningKey, "!!!not-base64!!!")
	if _, err := LoadSignerFromEnv("unit-test-1"); err == nil {
		t.Fatal("signer loaded with undecodable key")
	}
	t.Setenv(EnvSigningKey, base64.RawURLEncoding.EncodeToString([]byte("too-short")))
	if _, err := LoadSignerFromEnv("unit-test-1"); err == nil {
		t.Fatal("signer loaded with wrongly sized key")
	}
}

func TestLoadSignerFromEnvRoundTrip(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvSigningKey, base64.RawURLEncoding.EncodeToString(private))
	signer, err := LoadSignerFromEnv("unit-test-1")
	if err != nil {
		t.Fatal(err)
	}
	seedSigner, err := NewSigner("unit-test-1", private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if signer.PublicKey() != seedSigner.PublicKey() {
		t.Fatal("seed and full-key loading diverge")
	}
}

func TestDirectoryLoadFailsClosed(t *testing.T) {
	if _, err := LoadDirectory(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("directory loaded from absent path")
	}
	t.Setenv(EnvKeyDirectory, "")
	if _, err := LoadDirectoryFromEnv(); err == nil {
		t.Fatal("directory loaded without KEY_DIRECTORY_PATH")
	}
	if _, err := ParseDirectory([]byte(`{}`)); err == nil {
		t.Fatal("empty directory accepted")
	}
	if _, err := ParseDirectory([]byte(`{"kid-1":"!!!"}`)); err == nil {
		t.Fatal("undecodable key accepted")
	}
	short := base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, err := ParseDirectory([]byte(`{"kid-1":"` + short + `"}`)); err == nil {
		t.Fatal("wrongly sized key accepted")
	}
}

func TestDirectoryLoadFromFile(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	path := filepath.Join(t.TempDir(), "keys.json")
	content := []byte(`{"unit-test-1":"` + signer.PublicKey() + `"}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := LoadDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.VerifyEnvelope(signedTestEnvelope(t, signer)); err != nil {
		t.Fatalf("file-loaded directory rejected valid envelope: %v", err)
	}
}

func TestSignatureIsDetachedFromFieldOrder(t *testing.T) {
	signer := testSigner(t, "unit-test-1")
	directory := directoryWith(t, signer)
	raw := signedTestEnvelope(t, signer)
	// Re-marshal through a map: key order changes, signature must still hold.
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	remarshaled, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if string(remarshaled) == string(raw) {
		t.Fatal("fixture did not reorder keys")
	}
	if err := directory.VerifyEnvelope(remarshaled); err != nil {
		t.Fatalf("reordered envelope rejected: %v", err)
	}
}

func TestCanonicalNumbers(t *testing.T) {
	cases := map[string]string{
		`{"v":0}`:                   `{"v":0}`,
		`{"v":-0}`:                  `{"v":0}`,
		`{"v":1}`:                   `{"v":1}`,
		`{"v":-1}`:                  `{"v":-1}`,
		`{"v":3.14}`:                `{"v":3.14}`,
		`{"v":1e2}`:                 `{"v":100}`,
		`{"v":1.50}`:                `{"v":1.5}`,
		`{"v":0.000001}`:            `{"v":0.000001}`,
		`{"v":1e-7}`:                `{"v":1e-7}`,
		`{"v":1e21}`:                `{"v":1e+21}`,
		`{"v":1e20}`:                `{"v":100000000000000000000}`,
		`{"v":12345678901234567890}`: `{"v":12345678901234567000}`,
		`{"v":5e-7}`:                `{"v":5e-7}`,
		`{"v":-2.5e-8}`:             `{"v":-2.5e-8}`,
	}
	for input, expected := range cases {
		document, err := decodeJSON([]byte(input))
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		canonical, err := Canonicalize(document)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		if string(canonical) != expected {
			t.Fatalf("%s: got %s, want %s", input, canonical, expected)
		}
	}
}

func TestCanonicalStringsAndKeyOrder(t *testing.T) {
	document, err := decodeJSON([]byte(`{"b":1,"a":"quote\" back\\ newline\n tab\t","é":true,"A":[3,2,1]}`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"A":[3,2,1],"a":"quote\" back\\ newline\n tab\t","b":1,"é":true}`
	if string(canonical) != expected {
		t.Fatalf("got %s, want %s", canonical, expected)
	}
}

func TestSignedPayloadRejectsMalformed(t *testing.T) {
	for _, raw := range []string{`[1,2]`, `"text"`, `{"provenance":"x"}`, `{not json`} {
		if _, _, err := SignedPayload([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
}
