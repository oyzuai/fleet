// Package idtoken verifies the RS256 JSON Web Tokens that Google Compute
// Engine and Azure managed identities issue to an instance, against the
// issuer's published JSON Web Key Set. It checks the signature, issuer,
// audience and lifetime; the cloud adapters check their own claims.
package idtoken

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Skew is how far the issuer's clock may be from ours.
const Skew = time.Minute

// Keys finds the RSA public key a token's kid names.
type Keys interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Policy is what a token must say about where it came from.
type Policy struct {
	// Issuers lists the accepted iss values.
	Issuers []string
	// Audience must appear in aud.
	Audience string
}

// Verify checks token's signature with keys and its iss, aud, exp and nbf
// against p at now, then decodes its claims into claims.
func Verify(ctx context.Context, keys Keys, p Policy, token string, now time.Time, claims any) error {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return errors.New("the token is not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodePart(parts[0], &header); err != nil {
		return fmt.Errorf("the token header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("the token is signed with %q, not RS256", header.Alg)
	}
	key, err := keys.Key(ctx, header.Kid)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("the token signature: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return errors.New("the token's signature does not verify")
	}
	var std struct {
		Iss string   `json:"iss"`
		Aud audience `json:"aud"`
		Exp *int64   `json:"exp"`
		Nbf *int64   `json:"nbf"`
	}
	if err := decodePart(parts[1], &std); err != nil {
		return fmt.Errorf("the token claims: %w", err)
	}
	switch {
	case !slices.Contains(p.Issuers, std.Iss):
		return fmt.Errorf("the token's issuer %q is not accepted", std.Iss)
	case p.Audience == "" || !slices.Contains(std.Aud, p.Audience):
		return fmt.Errorf("the token is for %v, not %q", []string(std.Aud), p.Audience)
	case std.Exp == nil:
		return errors.New("the token has no expiry")
	case now.After(time.Unix(*std.Exp, 0).Add(Skew)):
		return errors.New("the token has expired")
	case std.Nbf != nil && now.Add(Skew).Before(time.Unix(*std.Nbf, 0)):
		return errors.New("the token is not valid yet")
	}
	return decodePart(parts[1], claims)
}

func decodePart(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// audience is aud, a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte(`"`)) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

// refreshEvery is how often a JWKS is fetched again; refreshMin is the
// least time between fetches when a token names a kid not yet seen, so a
// stream of bad tokens cannot hammer the issuer.
const (
	refreshEvery = time.Hour
	refreshMin   = time.Minute
)

// JWKS fetches and caches the keys an issuer publishes at URL.
type JWKS struct {
	URL    string
	Client *http.Client
	// Now is time.Now when nil.
	Now func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// Key implements Keys, fetching the set when it is stale or lacks kid.
func (j *JWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	k, ok := j.keys[kid]
	age := now.Sub(j.fetched)
	if (ok && age < refreshEvery) || (!ok && j.keys != nil && age < refreshMin) {
		if !ok {
			return nil, fmt.Errorf("no key %q in %s", kid, j.URL)
		}
		return k, nil
	}
	keys, err := j.fetch(ctx)
	if err != nil {
		if ok {
			// A key we already trust survives the issuer being unreachable.
			return k, nil
		}
		return nil, err
	}
	j.keys, j.fetched = keys, now
	if k, ok = keys[kid]; !ok {
		return nil, fmt.Errorf("no key %q in %s", kid, j.URL)
	}
	return k, nil
}

func (j *JWKS) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	c := j.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", j.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", j.URL, resp.Status)
	}
	return ParseJWKS(io.LimitReader(resp.Body, 1<<20))
}

// ParseJWKS reads the RSA signing keys from a JSON Web Key Set.
func ParseJWKS(r io.Reader) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(r).Decode(&set); err != nil {
		return nil, fmt.Errorf("the key set is not JSON: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) > 4 {
			continue
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(out) == 0 {
		return nil, errors.New("the key set has no RSA signing keys")
	}
	return out, nil
}
