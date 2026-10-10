// Package idtokentest signs instance identity tokens for tests, standing in
// for Google's or Microsoft's signing keys.
package idtokentest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// Signer is an issuer's signing key, and the Keys that publishes it.
type Signer struct {
	Kid string
	key *rsa.PrivateKey
}

// New returns a signer with a fresh 2048-bit key.
func New(t testing.TB, kid string) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Kid: kid, key: key}
}

// Key implements idtoken.Keys.
func (s *Signer) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	if kid != s.Kid {
		return nil, fmt.Errorf("no key %q", kid)
	}
	return &s.key.PublicKey, nil
}

// Public is the signer's public key.
func (s *Signer) Public() *rsa.PublicKey { return &s.key.PublicKey }

// Sign returns an RS256 JWT carrying claims.
func (s *Signer) Sign(t testing.TB, claims any) string {
	t.Helper()
	return s.SignAlg(t, "RS256", claims)
}

// SignAlg is Sign with another alg in the header, for refusal tests.
func (s *Signer) SignAlg(t testing.TB, alg string, claims any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(map[string]string{"alg": alg, "kid": s.Kid, "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}
