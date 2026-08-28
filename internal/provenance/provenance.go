// Package provenance implements the fleet envelope provenance signature
// scheme.
//
// provenance.signature is a JWS compact serialization (EdDSA/Ed25519) over
// the JCS-canonicalized (RFC 8785) JSON of the full envelope excluding the
// signature field. The JWS protected header is {"alg":"EdDSA","kid":
// "<producer>-<epoch>"}. Producer private keys arrive through the
// PROVENANCE_SIGNING_KEY environment variable (base64url Ed25519 private key
// or seed); producers fail closed at startup when it is absent or invalid.
// Consumers load the public-key directory JSON ({kid:
// base64url-ed25519-pubkey}) from the path named by KEY_DIRECTORY_PATH and
// fail closed when it is unreadable or empty.
package provenance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	// EnvSigningKey names the environment variable carrying the producer
	// base64url Ed25519 private key (64-byte key or 32-byte seed).
	EnvSigningKey = "PROVENANCE_SIGNING_KEY"
	// EnvKeyDirectory names the environment variable carrying the path of
	// the mounted public-key directory JSON document.
	EnvKeyDirectory = "KEY_DIRECTORY_PATH"
	// Algorithm is the only accepted JWS algorithm.
	Algorithm = "EdDSA"

	maxDirectoryBytes = 1 << 20
	maxKidLength      = 128
)

// Signer signs envelope provenance with one producer key.
type Signer struct {
	kid string
	key ed25519.PrivateKey
}

// NewSigner validates the key id and private key. The key id must be
// canonical non-empty text; the key must be a 64-byte Ed25519 private key or
// a 32-byte seed.
func NewSigner(kid string, key []byte) (*Signer, error) {
	if err := validateKid(kid); err != nil {
		return nil, err
	}
	var private ed25519.PrivateKey
	switch len(key) {
	case ed25519.PrivateKeySize:
		private = ed25519.PrivateKey(append([]byte(nil), key...))
	case ed25519.SeedSize:
		private = ed25519.NewKeyFromSeed(append([]byte(nil), key...))
	default:
		return nil, fmt.Errorf("Ed25519 private key must be %d bytes (key) or %d bytes (seed)", ed25519.PrivateKeySize, ed25519.SeedSize)
	}
	return &Signer{kid: kid, key: private}, nil
}

// LoadSignerFromEnv resolves the producer signing key from PROVENANCE_SIGNING_KEY.
// It fails closed: an absent, undecodable or wrongly sized key is a startup
// error, never a disabled signer.
func LoadSignerFromEnv(kid string) (*Signer, error) {
	value := strings.TrimSpace(os.Getenv(EnvSigningKey))
	if value == "" {
		return nil, fmt.Errorf("%s is required; provenance signing is mandatory", EnvSigningKey)
	}
	key, err := decodeBase64URL(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64url: %w", EnvSigningKey, err)
	}
	return NewSigner(kid, key)
}

// KeyID returns the signer key id carried in the JWS protected header.
func (s *Signer) KeyID() string { return s.kid }

// PublicKey returns the base64url public half, for key-directory assembly.
func (s *Signer) PublicKey() string {
	public := s.key.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(public)
}

// Sign produces the JWS compact serialization of payload with the protected
// header {"alg":"EdDSA","kid":<kid>}.
func (s *Signer) Sign(payload []byte) (string, error) {
	if s == nil || len(s.key) == 0 {
		return "", errors.New("provenance signer is required")
	}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{Alg: Algorithm, Kid: s.kid})
	if err != nil {
		return "", fmt.Errorf("encode JWS header: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.key, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// SignEnvelope signs one envelope document: the JWS payload is the
// JCS-canonicalized JSON of the full envelope excluding the
// provenance.signature field.
func (s *Signer) SignEnvelope(envelope any) (string, error) {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("encode envelope for signing: %w", err)
	}
	payload, _, err := SignedPayload(raw)
	if err != nil {
		return "", err
	}
	return s.Sign(payload)
}

// SignedPayload returns the JCS-canonical bytes of the envelope document in
// raw with provenance.signature removed, plus the removed signature value
// ("" when absent). It fails closed on malformed JSON, a non-object envelope
// or a non-object provenance member.
func SignedPayload(raw []byte) ([]byte, string, error) {
	document, err := decodeJSON(raw)
	if err != nil {
		return nil, "", fmt.Errorf("decode envelope for provenance: %w", err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return nil, "", errors.New("envelope is not a JSON object")
	}
	provenance, ok := object["provenance"].(map[string]any)
	if !ok {
		return nil, "", errors.New("envelope provenance is not a JSON object")
	}
	signature, _ := provenance["signature"].(string)
	delete(provenance, "signature")
	canonical, err := Canonicalize(document)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize envelope: %w", err)
	}
	return canonical, signature, nil
}

// Directory is the consumer-side public-key directory ({kid: Ed25519 public
// key}) used to verify envelope provenance signatures.
type Directory struct {
	keys map[string]ed25519.PublicKey
}

// LoadDirectory reads and validates the key-directory JSON document at path.
// It fails closed: an unreadable, malformed or empty directory, an
// undecodable key, or an invalid key id is an error.
func LoadDirectory(path string) (*Directory, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("key directory path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key directory: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxDirectoryBytes {
		return nil, fmt.Errorf("key directory %q is not a regular file between 1 and %d bytes", path, maxDirectoryBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key directory: %w", err)
	}
	return ParseDirectory(raw)
}

// LoadDirectoryFromEnv resolves KEY_DIRECTORY_PATH and loads the directory.
func LoadDirectoryFromEnv() (*Directory, error) {
	path := strings.TrimSpace(os.Getenv(EnvKeyDirectory))
	if path == "" {
		return nil, fmt.Errorf("%s is required; provenance verification is mandatory", EnvKeyDirectory)
	}
	return LoadDirectory(path)
}

// ParseDirectory validates one key-directory JSON document.
func ParseDirectory(raw []byte) (*Directory, error) {
	if len(raw) == 0 || len(raw) > maxDirectoryBytes {
		return nil, fmt.Errorf("key directory must be between 1 and %d bytes", maxDirectoryBytes)
	}
	document, err := decodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("decode key directory: %w", err)
	}
	object, ok := document.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, errors.New("key directory must be a non-empty JSON object of kid to base64url public key")
	}
	keys := make(map[string]ed25519.PublicKey, len(object))
	for kid, value := range object {
		if err := validateKid(kid); err != nil {
			return nil, fmt.Errorf("key directory entry: %w", err)
		}
		encoded, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("key directory entry %q is not a base64url string", kid)
		}
		key, err := decodeBase64URL(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key directory entry %q is not a %d-byte base64url Ed25519 public key", kid, ed25519.PublicKeySize)
		}
		keys[kid] = ed25519.PublicKey(key)
	}
	return &Directory{keys: keys}, nil
}

// KeyIDs returns the sorted directory key ids (for startup logging).
func (d *Directory) KeyIDs() []string {
	ids := make([]string, 0, len(d.keys))
	for kid := range d.keys {
		ids = append(ids, kid)
	}
	sort.Strings(ids)
	return ids
}

// Verify checks one JWS compact serialization against payload using the
// directory key named by the protected header kid. The signed input is
// re-derived from the supplied payload, so a JWS whose payload segment does
// not match the expected payload fails as an invalid signature. Unknown
// kids, malformed JWS, unexpected algorithms and invalid signatures are
// distinct errors so callers can log and meter the rejection reason.
func (d *Directory) Verify(payload []byte, jws string) error {
	kid, headerSegment, signature, err := parseJWS(jws)
	if err != nil {
		return err
	}
	if d == nil {
		return errors.New("key directory is required")
	}
	key, ok := d.keys[kid]
	if !ok {
		return fmt.Errorf("unknown provenance key id %q", kid)
	}
	input := headerSegment + "." + base64.RawURLEncoding.EncodeToString(payload)
	if !ed25519.Verify(key, []byte(input), signature) {
		return errors.New("provenance signature verification failed")
	}
	return nil
}

// VerifyEnvelope verifies the provenance signature carried by the raw
// envelope document: the payload is the JCS canonicalization of the envelope
// excluding provenance.signature. An absent or non-string signature is a
// malformed-JWS rejection.
func (d *Directory) VerifyEnvelope(raw []byte) error {
	payload, signature, err := SignedPayload(raw)
	if err != nil {
		return err
	}
	if signature == "" {
		return errors.New("envelope provenance signature is missing")
	}
	return d.Verify(payload, signature)
}

// parseJWS decodes one JWS compact serialization and returns the key id, the
// protected-header segment and the raw signature. The payload segment is
// validated as base64url but never trusted: callers re-derive the signed
// input from the expected payload.
func parseJWS(jws string) (kid, headerSegment string, signature []byte, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", nil, errors.New("JWS compact serialization must have three non-empty segments")
	}
	headerRaw, err := decodeBase64URL(parts[0])
	if err != nil {
		return "", "", nil, fmt.Errorf("JWS protected header is not base64url: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	decoder := json.NewDecoder(bytes.NewReader(headerRaw))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&header); decodeErr != nil {
		return "", "", nil, fmt.Errorf("JWS protected header is invalid: %w", decodeErr)
	}
	if header.Alg != Algorithm {
		return "", "", nil, fmt.Errorf("JWS algorithm %q is not %q", header.Alg, Algorithm)
	}
	if err := validateKid(header.Kid); err != nil {
		return "", "", nil, fmt.Errorf("JWS key id: %w", err)
	}
	if _, err := decodeBase64URL(parts[1]); err != nil {
		return "", "", nil, fmt.Errorf("JWS payload is not base64url: %w", err)
	}
	signature, err = decodeBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", "", nil, errors.New("JWS signature is not a base64url Ed25519 signature")
	}
	return header.Kid, parts[0], signature, nil
}

func validateKid(kid string) error {
	if kid == "" || len(kid) > maxKidLength || strings.TrimSpace(kid) != kid || strings.ContainsAny(kid, "\". \t\r\n") {
		return fmt.Errorf("key id %q is not canonical non-empty text of at most %d bytes", kid, maxKidLength)
	}
	return nil
}

// decodeBase64URL accepts unpadded or padded URL-safe base64 only.
func decodeBase64URL(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func decodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing data after JSON document")
	}
	return document, nil
}

// Canonicalize serializes one decoded JSON value (maps, slices, strings,
// json.Number, bool, nil) per RFC 8785 (JSON Canonicalization Scheme).
func Canonicalize(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := canonicalValue(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func canonicalValue(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		canonicalString(buffer, typed)
	case json.Number:
		formatted, err := canonicalNumber(typed.String())
		if err != nil {
			return err
		}
		buffer.WriteString(formatted)
	case float64:
		formatted, err := canonicalNumber(strconv.FormatFloat(typed, 'g', -1, 64))
		if err != nil {
			return err
		}
		buffer.WriteString(formatted)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := canonicalValue(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			canonicalString(buffer, key)
			buffer.WriteByte(':')
			if err := canonicalValue(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("value of type %T is not JSON-canonicalizable", value)
	}
	return nil
}

// canonicalString emits one JSON string with the minimal RFC 8785 escape set.
func canonicalString(buffer *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	buffer.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			if r < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(hexDigits[(r>>4)&0xf])
				buffer.WriteByte(hexDigits[r&0xf])
			} else {
				buffer.WriteRune(r)
			}
		}
	}
	buffer.WriteByte('"')
}

// canonicalNumber renders one JSON number per the ECMAScript Number-to-String
// algorithm required by RFC 8785. The number is interpreted as an IEEE 754
// double.
func canonicalNumber(literal string) (string, error) {
	value, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		return "", fmt.Errorf("number %q is not a valid double: %w", literal, err)
	}
	if value == 0 {
		return "0", nil
	}
	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}
	// Shortest round-trip decimal: "d", "d.ddd", with an exponent when needed.
	shortest := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa := shortest
	exponent := 0
	if index := strings.IndexByte(shortest, 'e'); index >= 0 {
		mantissa = shortest[:index]
		parsed, convErr := strconv.Atoi(shortest[index+1:])
		if convErr != nil {
			return "", fmt.Errorf("number %q has an invalid exponent", literal)
		}
		exponent = parsed
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	// value = digits * 10^(n-k); n is the decimal point position.
	n := exponent + 1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	default:
		exponentSign := "+"
		exponentValue := n - 1
		if exponentValue < 0 {
			exponentSign = "-"
			exponentValue = -exponentValue
		}
		mantissaOut := digits[:1]
		if k > 1 {
			mantissaOut += "." + digits[1:]
		}
		return sign + mantissaOut + "e" + exponentSign + strconv.Itoa(exponentValue), nil
	}
}

// utf16Less orders object keys by UTF-16 code units as RFC 8785 requires.
func utf16Less(a, b string) bool {
	au, bu := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}
