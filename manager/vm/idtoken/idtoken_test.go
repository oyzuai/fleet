package idtoken_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager/vm/idtoken"
	"github.com/oyzuai/fleet/manager/vm/idtoken/idtokentest"
)

var policy = idtoken.Policy{Issuers: []string{"https://issuer.test"}, Audience: "oyzu-pool"}

func claims(mod func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{"iss": "https://issuer.test", "aud": "oyzu-pool", "iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(), "sub": "instance-1"}
	if mod != nil {
		mod(c)
	}
	return c
}

func TestVerify(t *testing.T) {
	s := idtokentest.New(t, "k1")
	ctx := context.Background()
	var got struct {
		Sub string `json:"sub"`
	}
	if err := idtoken.Verify(ctx, s, policy, s.Sign(t, claims(nil)), time.Now(), &got); err != nil || got.Sub != "instance-1" {
		t.Fatalf("verify = %+v, %v", got, err)
	}
	listAud := claims(func(c map[string]any) { c["aud"] = []string{"other", "oyzu-pool"} })
	if err := idtoken.Verify(ctx, s, policy, s.Sign(t, listAud), time.Now(), &got); err != nil {
		t.Fatalf("aud as a list: %v", err)
	}
	other := idtokentest.New(t, "k1")
	for name, tok := range map[string]string{
		"other audience": s.Sign(t, claims(func(c map[string]any) { c["aud"] = "someone-else" })),
		"other issuer":   s.Sign(t, claims(func(c map[string]any) { c["iss"] = "https://evil.test" })),
		"expired":        s.Sign(t, claims(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"no expiry":      s.Sign(t, claims(func(c map[string]any) { delete(c, "exp") })),
		"not yet valid":  s.Sign(t, claims(func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() })),
		"other key":      other.Sign(t, claims(nil)),
		"HS256":          s.SignAlg(t, "HS256", claims(nil)),
		"not a JWT":      "abc.def",
	} {
		if err := idtoken.Verify(ctx, s, policy, tok, time.Now(), &got); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Claims edited after signing do not verify.
	parts := strings.Split(s.Sign(t, claims(nil)), ".")
	b, _ := json.Marshal(claims(func(c map[string]any) { c["sub"] = "instance-2" }))
	parts[1] = base64.RawURLEncoding.EncodeToString(b)
	if err := idtoken.Verify(ctx, s, policy, strings.Join(parts, "."), time.Now(), &got); err == nil {
		t.Error("tampered claims verified")
	}
}

func TestJWKSFetchesCachesAndRefreshes(t *testing.T) {
	s := idtokentest.New(t, "k1")
	pub := s.Public()
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "EC", "kid": "ec"},
			{"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())},
		}})
	}))
	defer srv.Close()
	now := time.Now()
	j := &idtoken.JWKS{URL: srv.URL, Client: srv.Client(), Now: func() time.Time { return now }}
	ctx := context.Background()
	if err := idtoken.Verify(ctx, j, policy, s.Sign(t, claims(nil)), time.Now(), &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Key(ctx, "k1"); err != nil || fetches.Load() != 1 {
		t.Fatalf("cached key: %v after %d fetches", err, fetches.Load())
	}
	// An unknown kid refetches, but not more than once a minute.
	if _, err := j.Key(ctx, "k2"); err == nil {
		t.Fatal("an unknown kid was found")
	}
	if _, err := j.Key(ctx, "k2"); err == nil || fetches.Load() != 1 {
		t.Fatalf("unknown kid refetched too soon: %d fetches", fetches.Load())
	}
	now = now.Add(2 * time.Minute)
	if _, err := j.Key(ctx, "k2"); err == nil || fetches.Load() != 2 {
		t.Fatalf("unknown kid after a minute: %d fetches", fetches.Load())
	}
	// A known key survives the issuer going away.
	srv.Close()
	now = now.Add(2 * time.Hour)
	if _, err := j.Key(ctx, "k1"); err != nil {
		t.Fatalf("known key with the issuer down: %v", err)
	}
}
