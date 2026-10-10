// Package assertion signs and verifies the compact EdDSA JWTs a pool manager
// sends instead of a password: private_key_jwt client assertions for login
// (RFC 7523) and key rotation requests signed by the current key.
//
// It is deliberately small: one algorithm (Ed25519), the claims runs uses, and
// strict checks. A token with any other algorithm, a missing claim or a
// lifetime longer than MaxLifetime is rejected before its signature is used.
package assertion

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// TypeLogin is the typ of a login assertion.
	TypeLogin = "JWT"
	// TypeRotation is the typ of a request to register the manager's next key.
	// A distinct typ keeps a rotation request from being accepted as a login
	// and the other way round.
	TypeRotation = "oyzu-key-rotation+jwt"
	// MaxLifetime bounds exp - iat. An assertion is used once, right away.
	MaxLifetime = 5 * time.Minute
	// Skew is the clock drift tolerated on iat and exp.
	Skew = time.Minute
	// maxSize bounds what is decoded at all.
	maxSize = 4 << 10
)

// Claims are the claims runs reads. Issuer and Subject are both the manager
// id, as private_key_jwt requires.
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	ID       string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	// NewKey is the base64url Ed25519 public key a rotation request registers.
	NewKey string `json:"new_key,omitempty"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Sign returns the compact JWT for claims, signed with key and naming keyID.
func Sign(key ed25519.PrivateKey, keyID int64, typ string, c Claims) (string, error) {
	h, err := json.Marshal(header{Alg: "EdDSA", Typ: typ, Kid: strconv.FormatInt(keyID, 10)})
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(b)
	return input + "." + enc.EncodeToString(ed25519.Sign(key, []byte(input))), nil
}

// New returns claims for manager to send to audience now, valid for ttl.
func New(manager int64, audience, jti string, now time.Time, ttl time.Duration) Claims {
	id := strconv.FormatInt(manager, 10)
	return Claims{Issuer: id, Subject: id, Audience: audience, ID: jti, IssuedAt: now.Unix(), Expires: now.Add(ttl).Unix()}
}

// Parsed is a structurally valid assertion whose signature is not yet checked.
type Parsed struct {
	KeyID  int64
	Type   string
	Claims Claims
	input  string
	sig    []byte
}

// Parse decodes token and checks its shape: EdDSA, a numeric kid, and the
// claims present. It does not check the signature or the time.
func Parse(token string) (*Parsed, error) {
	if len(token) > maxSize {
		return nil, errors.New("the assertion is too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the assertion is not a compact JWT")
	}
	enc := base64.RawURLEncoding
	var h header
	if err := decode(parts[0], &h); err != nil {
		return nil, fmt.Errorf("the assertion header: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("the assertion is signed with %q, not EdDSA", h.Alg)
	}
	kid, err := strconv.ParseInt(h.Kid, 10, 64)
	if err != nil || kid <= 0 {
		return nil, errors.New("the assertion has no key id")
	}
	var c Claims
	if err := decode(parts[1], &c); err != nil {
		return nil, fmt.Errorf("the assertion claims: %w", err)
	}
	if c.Issuer == "" || c.Issuer != c.Subject || c.Audience == "" || c.ID == "" || len(c.ID) > 200 ||
		c.IssuedAt == 0 || c.Expires == 0 {
		return nil, errors.New("the assertion needs iss equal to sub, aud, jti, iat and exp")
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("the assertion signature is malformed")
	}
	return &Parsed{KeyID: kid, Type: h.Typ, Claims: c, input: parts[0] + "." + parts[1], sig: sig}, nil
}

func decode(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return errors.New("not base64url")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("not a JSON object")
	}
	return nil
}

// Manager is the manager id the assertion claims to come from.
func (p *Parsed) Manager() (int64, error) {
	id, err := strconv.ParseInt(p.Claims.Issuer, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("the assertion issuer is not a manager id")
	}
	return id, nil
}

// Expires is when the assertion stops being valid.
func (p *Parsed) Expires() time.Time { return time.Unix(p.Claims.Expires, 0) }

// Verify checks the signature against key, the type, the audience and the
// time window. Call it before trusting anything in the claims.
func (p *Parsed) Verify(key ed25519.PublicKey, typ, audience string, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(p.input), p.sig) {
		return errors.New("the assertion signature does not verify")
	}
	if p.Type != typ {
		return fmt.Errorf("the assertion type is %q, want %q", p.Type, typ)
	}
	if p.Claims.Audience != audience {
		return errors.New("the assertion is for another audience")
	}
	iat, exp := time.Unix(p.Claims.IssuedAt, 0), time.Unix(p.Claims.Expires, 0)
	switch {
	case !exp.After(iat) || exp.Sub(iat) > MaxLifetime:
		return fmt.Errorf("the assertion must expire within %s of being issued", MaxLifetime)
	case iat.After(now.Add(Skew)):
		return errors.New("the assertion is issued in the future")
	case !exp.Add(Skew).After(now):
		return errors.New("the assertion has expired")
	}
	return nil
}

// EncodeKey renders a public key as base64url, as enrollment and rotation send it.
func EncodeKey(k ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(k) }

// DecodeKey parses a base64url Ed25519 public key.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("the public key is not a base64url Ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}
