// ticket-keygen provisions the Ed25519 ticket signing key for ferry-api: it
// writes a freshly generated key to the given file (mode 0600, base64url of
// the 64-byte private key) and prints the public key and kid for verifier
// distribution. Keys are generated at runtime; nothing is ever committed.
//
// Usage: ticket-keygen /path/to/signing-key.b64
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ticket-keygen <output-key-file>")
		os.Exit(2)
	}
	path := filepath.Clean(os.Args[1])
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(private)+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write key file: %v\n", err)
		os.Exit(1)
	}
	digest := sha256.Sum256(public)
	fmt.Printf("wrote %s (mode 0600)\n", path)
	fmt.Printf("public key (base64url): %s\n", base64.RawURLEncoding.EncodeToString(public))
	fmt.Printf("kid (base64url):        %s\n", base64.RawURLEncoding.EncodeToString(digest[:8]))
}
