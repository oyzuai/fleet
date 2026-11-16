package runnerclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActionClientBindsRoutesAndValidatesFileIdentity(t *testing.T) {
	b := []byte("input")
	sum := sha256.Sum256(b)
	f := ActionFile{Path: "input", Data: b, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
	finished := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer live-job" {
			t.Error("wrong assignment authority")
		}
		switch r.URL.Path {
		case "/runner/v1/job/action/inputs":
			json.NewEncoder(w).Encode(ActionInputs{Files: []ActionFile{f}})
		case "/runner/v1/job/action/finish":
			var out ActionCompletion
			if err := json.NewDecoder(r.Body).Decode(&out); err != nil || !out.TerminationConfirmed {
				t.Error("invalid completion")
			}
			finished = true
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	c := New(s.URL, nil)
	in, err := c.ActionInputs(context.Background(), "live-job")
	if err != nil || len(in.Files) != 1 {
		t.Fatalf("inputs: %+v %v", in, err)
	}
	if err := c.ActionFinish(context.Background(), "live-job", ActionCompletion{TerminationConfirmed: true, Files: in.Files}); err != nil || !finished {
		t.Fatalf("finish: %v", err)
	}
	for _, p := range []string{"../secret", "/secret", "dir/../secret", `dir\secret`, "a:b", "a\x00b"} {
		f.Path = p
		if err := (ActionInputs{Files: []ActionFile{f}}).Validate(); err == nil {
			t.Fatalf("accepted path %q", p)
		}
	}
	f.Path = "input"
	f.SHA256 = strings.Repeat("0", 64)
	if err := (ActionInputs{Files: []ActionFile{f}}).Validate(); err == nil {
		t.Fatal("accepted wrong digest")
	}
}
