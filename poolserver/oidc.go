package poolserver

// Independently implemented for the same trust boundary as platform's cache
// gate: a fixed GitHub issuer, RS256, published RSA keys and a pinned audience.
import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type oidcAudience []string

func (a *oidcAudience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = []string{s}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(a))
}

type oidcClaims struct {
	Issuer     string       `json:"iss"`
	Audience   oidcAudience `json:"aud"`
	Expiry     int64        `json:"exp"`
	NotBefore  int64        `json:"nbf"`
	Subject    string       `json:"sub"`
	Repository string       `json:"repository"`
	SHA        string       `json:"sha"`
	Ref        string       `json:"ref"`
	RunID      string       `json:"run_id"`
	RunAttempt string       `json:"run_attempt"`
}
type oidcVerifier struct {
	audience, jwksURL string
	client            *http.Client
	now               func() time.Time
	mu                sync.Mutex
	keys              map[string]*rsa.PublicKey
	fetched           time.Time
	attempts          map[string]time.Time
}

func (v *oidcVerifier) verify(ctx context.Context, token string) (*oidcClaims, error) {
	if len(token) > 32<<10 {
		return nil, errors.New("oversized JWT")
	}
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, errors.New("invalid JWT")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if decodeJWT(p[0], &h) != nil || h.Alg != "RS256" || h.Kid == "" || len(h.Kid) > 200 {
		return nil, errors.New("invalid signing algorithm or key")
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return nil, errors.New("invalid signature")
	}
	var c oidcClaims
	if decodeJWT(p[1], &c) != nil {
		return nil, errors.New("invalid claims")
	}
	now := v.now().Unix()
	if c.Issuer != "https://token.actions.githubusercontent.com" || !contains(c.Audience, v.audience) || c.Expiry <= now || c.NotBefore > now {
		return nil, errors.New("untrusted or expired claims")
	}
	return &c, nil
}
func decodeJWT(s string, v any) error {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (v *oidcVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	key := v.keys[kid]
	// A new kid triggers a refresh immediately, including just after rotation.
	// Bound attacker-controlled unknown-kid requests across the whole verifier.
	last := v.attempts[kid]
	global := v.attempts[""]
	refresh := key == nil || now.Sub(v.fetched) >= time.Hour
	if refresh && (last.IsZero() || now.Sub(last) >= time.Minute) && (global.IsZero() || now.Sub(global) >= time.Second) {
		if v.attempts == nil {
			v.attempts = map[string]time.Time{}
		}
		if len(v.attempts) > 256 {
			v.attempts = map[string]time.Time{}
		}
		v.attempts[kid] = now
		v.attempts[""] = now
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := v.client.Do(req)
		if err != nil {
			return nil, errors.New("issuer keys unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New("issuer keys unavailable")
		}
		var set struct {
			Keys []struct {
				Kty string `json:"kty"`
				Kid string `json:"kid"`
				Alg string `json:"alg"`
				Use string `json:"use"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set) != nil {
			return nil, errors.New("invalid key set")
		}
		keys := map[string]*rsa.PublicKey{}
		for _, k := range set.Keys {
			n, ne := base64.RawURLEncoding.DecodeString(k.N)
			e, ee := base64.RawURLEncoding.DecodeString(k.E)
			if k.Kty != "RSA" || k.Kid == "" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") || ne != nil || ee != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			mod := new(big.Int).SetBytes(n)
			ex := int(new(big.Int).SetBytes(e).Int64())
			if mod.BitLen() < 2048 || mod.BitLen() > 8192 || ex < 3 || ex%2 == 0 {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: mod, E: ex}
		}
		if len(keys) == 0 {
			return nil, errors.New("empty key set")
		}
		v.keys = keys
		v.fetched = now
		key = keys[kid]
	}
	if key == nil {
		return nil, errors.New("unknown signing key")
	}
	return key, nil
}
