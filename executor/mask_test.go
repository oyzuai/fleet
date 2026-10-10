package executor

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func maskAll(t *testing.T, forms []string, writes ...string) string {
	t.Helper()
	var b strings.Builder
	m := newMaskWriter(&b, forms)
	for _, w := range writes {
		if _, err := m.Write([]byte(w)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// LOG-01: no form of a job credential gets through, however the build
// splits or encodes it.
func TestMaskForms(t *testing.T) {
	const secret = "ghs_s3cr3t/value+x"
	forms := maskForms(secret)
	cases := map[string][]string{
		"exact":         {"token=" + secret + "\n"},
		"split":         {"token=ghs_s", "3cr3t/va", "lue+x done\n"},
		"byte by byte":  strings.Split("a "+secret+" b\n", ""),
		"percent":       {"u=" + url.QueryEscape(secret) + "\n"},
		"path escape":   {"/" + url.PathEscape(secret) + "/\n"},
		"json":          {`{"t":"` + strings.ReplaceAll(secret, "/", `\/`) + `"}` + "\n"},
		"base64 std":    {base64.StdEncoding.EncodeToString([]byte(secret)) + "\n"},
		"base64 url":    {base64.URLEncoding.EncodeToString([]byte(secret)) + "\n"},
		"base64 align1": {base64.StdEncoding.EncodeToString([]byte("a"+secret+"zz")) + "\n"},
		"base64 align2": {base64.StdEncoding.EncodeToString([]byte("ab"+secret+"z")) + "\n"},
		"basic auth":    {"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secret)) + "\n"},
	}
	for name, writes := range cases {
		got := maskAll(t, forms, writes...)
		if strings.Contains(got, "s3cr3t") || !strings.Contains(got, masked) {
			t.Errorf("%s: %q", name, got)
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if core := base64Core(enc.WithPadding(base64.NoPadding), secret, 0); strings.Contains(got, core) {
				t.Errorf("%s: base64 form left in %q", name, got)
			}
		}
	}
}

func TestMaskMultiLineAndShort(t *testing.T) {
	key := "-----BEGIN KEY-----\nMIIabcdefgh\nMIIijklmnop\n-----END KEY-----"
	got := maskAll(t, maskForms(key, "abc"), "x\nMIIijklmnop\nabc\n")
	if got != "x\n***\nabc\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskReleasesSafeTextAtOnce(t *testing.T) {
	var b strings.Builder
	m := newMaskWriter(&b, maskForms("oyzu_job_ok"))
	_, _ = m.Write([]byte("progress 40% oyzu_j"))
	if b.String() != "progress 40% " {
		t.Fatalf("released %q before the next write", b.String())
	}
	_, _ = m.Write([]byte("unk\n"))
	_ = m.Flush()
	if b.String() != "progress 40% oyzu_junk\n" {
		t.Fatalf("got %q", b.String())
	}
}
