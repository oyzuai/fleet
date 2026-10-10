package assertion

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	tok, err := Sign(priv, 7, TypeLogin, New(3, "oyzu-runs", "j1", now, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := p.Manager(); p.KeyID != 7 || m != 3 || p.Claims.ID != "j1" {
		t.Fatalf("parsed = %+v", p)
	}
	if err := p.Verify(pub, TypeLogin, "oyzu-runs", now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	sign := func(typ string, c Claims) *Parsed {
		t.Helper()
		tok, err := Sign(priv, 1, typ, c)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(tok)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := New(1, "aud", "j", now, time.Minute)
	long := New(1, "aud", "j", now, time.Hour)
	expired := New(1, "aud", "j", now.Add(-10*time.Minute), time.Minute)
	future := New(1, "aud", "j", now.Add(10*time.Minute), time.Minute)
	for name, tc := range map[string]struct {
		p   *Parsed
		key ed25519.PublicKey
		typ string
		aud string
	}{
		"another key":       {sign(TypeLogin, good), other, TypeLogin, "aud"},
		"rotation as login": {sign(TypeRotation, good), pub, TypeLogin, "aud"},
		"another audience":  {sign(TypeLogin, good), pub, TypeLogin, "other"},
		"too long":          {sign(TypeLogin, long), pub, TypeLogin, "aud"},
		"expired":           {sign(TypeLogin, expired), pub, TypeLogin, "aud"},
		"future":            {sign(TypeLogin, future), pub, TypeLogin, "aud"},
	} {
		if err := tc.p.Verify(tc.key, tc.typ, tc.aud, now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestParseRejects(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok, _ := Sign(priv, 1, TypeLogin, New(1, "aud", "j", time.Now(), time.Minute))
	parts := strings.Split(tok, ".")
	noneHeader := "eyJhbGciOiJub25lIiwia2lkIjoiMSJ9" // {"alg":"none","kid":"1"}
	for name, s := range map[string]string{
		"two parts":  parts[0] + "." + parts[1],
		"alg none":   noneHeader + "." + parts[1] + "." + parts[2],
		"no claims":  parts[0] + ".e30." + parts[2],
		"bad sig":    parts[0] + "." + parts[1] + ".AAAA",
		"oversized":  strings.Repeat("a", 5000),
		"not base64": "!!." + parts[1] + "." + parts[2],
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestKeyEncoding(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	got, err := DecodeKey(EncodeKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	if _, err := DecodeKey("AAAA"); err == nil {
		t.Fatal("short key decoded")
	}
}
