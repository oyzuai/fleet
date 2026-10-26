package poolserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/oyzuai/fleet/runnerclient"
)

func uploadSource(t *testing.T, f *fixture, digest string, data []byte) int {
	return uploadSourceAs(t, f, digest, data, "micah@example.com")
}

func uploadSourceAs(t *testing.T, f *fixture, digest string, data []byte, login string) int {
	t.Helper()
	r := httptest.NewRequest("PUT", "/api/v1alpha1/accounts/oyzu/sources/"+digest, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Tailscale-User-Login", login)
	r.Header.Set("Content-Type", sourceMediaType)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w.Code
}

type forbiddenSnapshotGit struct{ calls atomic.Int32 }

func (s *forbiddenSnapshotGit) CommitExists(context.Context, string, string) (bool, error) {
	s.calls.Add(1)
	return false, errors.New("snapshot must not query GitHub")
}
func (s *forbiddenSnapshotGit) Source(context.Context, string) (runnerclient.Source, error) {
	s.calls.Add(1)
	return runnerclient.Source{}, errors.New("snapshot must not mint GitHub credentials")
}

func TestSnapshotUploadAndRunSource(t *testing.T) {
	f := newFixture(t)
	data, blob := sourceTestManifest(t, f, "content-addressed test file")
	digest := "sha256:" + hash(data)
	if got := uploadSource(t, f, digest, data); got != 201 {
		t.Fatalf("stored %d", got)
	}
	if got := uploadSource(t, f, digest, data); got != 200 {
		t.Fatalf("existing %d", got)
	}
	if got := uploadSource(t, f, digest, []byte("wrong")); got != 422 {
		t.Fatalf("digest mismatch %d", got)
	}
	git := &forbiddenSnapshotGit{}
	f.s.source = git // unpushed base commits are informational.
	body := RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Source: &SnapshotSource{Kind: "snapshot", Digest: digest, BaseCommit: testSHA}, Operation: Operation{Kind: "build"}}
	status, raw, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/runs", "micah@example.com", body, nil)
	if status != 201 {
		t.Fatalf("create %d %s", status, raw)
	}
	var run Run
	if err := json.Unmarshal(raw, &run); err != nil {
		t.Fatal(err)
	}
	if run.Source == nil || run.Source.Digest != digest || run.Commit != testSHA {
		t.Fatalf("source lost: %s", raw)
	}
	f.s.mu.Lock()
	j := f.s.state.Jobs[f.s.state.Runs[run.ID].JobID]
	if strings.Join(j.Job.Command, " ") != "oyzu build --isolated --full" {
		t.Fatalf("command %v", j.Job.Command)
	}
	j.State = "running"
	j.TokenHash = hash([]byte("job-test"))
	j.Lease = f.s.now().Add(2 * time.Minute)
	f.s.mu.Unlock()
	status, raw, _ = f.request(t, "POST", "/runner/v1/job/source", "", nil, map[string]string{"Authorization": "Bearer job-test"})
	if status != 200 {
		t.Fatalf("source %d %s", status, raw)
	}
	var source runnerclient.Source
	if err := json.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	if source.Kind != "snapshot" || source.Token != "" || source.Digest != digest {
		t.Fatalf("source %s", raw)
	}
	if git.calls.Load() != 0 {
		t.Fatalf("snapshot reached GitHub %d times", git.calls.Load())
	}
	u, _ := url.Parse(source.URL)
	resp, err := f.ts.Client().Get(f.ts.URL + u.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, data) {
		t.Fatalf("download %d %s", resp.StatusCode, got)
	}
	blobURL := strings.Replace(u.RequestURI(), "/sources/"+digest, "/blobs/"+blob, 1)
	resp, err = f.ts.Client().Get(f.ts.URL + blobURL)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(got) != "content-addressed test file" {
		t.Fatalf("blob download %d %q", resp.StatusCode, got)
	}
	outside := []byte("outside this manifest")
	outsideDigest := "sha256:" + hash(outside)
	if status, _ := putBlob(t, f, outsideDigest, outside, ""); status != 201 {
		t.Fatalf("outside blob upload %d", status)
	}
	resp, err = f.ts.Client().Get(f.ts.URL + strings.Replace(blobURL, blob, outsideDigest, 1))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("grant authorized unlisted blob: %d", resp.StatusCode)
	}
	f.now.Add(6 * 60)
	resp, err = f.ts.Client().Get(f.ts.URL + u.RequestURI())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expired grant %d", resp.StatusCode)
	}
}

func TestSnapshotDigestKnowledgeDoesNotGrantAnotherCallerAccess(t *testing.T) {
	f := newFixture(t)
	data, _ := sourceTestManifest(t, f, "private caller A file")
	digest := "sha256:" + hash(data)
	if got := uploadSource(t, f, digest, data); got != 201 {
		t.Fatalf("upload A %d", got)
	}
	body := RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Source: &SnapshotSource{Kind: "snapshot", Digest: digest}, Operation: Operation{Kind: "build"}}
	create := func() int {
		status, _, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/runs", "other@example.com", body, nil)
		return status
	}
	if got := create(); got != 403 {
		t.Fatalf("digest knowledge granted B access: %d", got)
	}
	if got := uploadSourceAs(t, f, digest, []byte("wrong"), "other@example.com"); got != 422 {
		t.Fatalf("incorrect body %d", got)
	}
	if got := create(); got != 403 {
		t.Fatalf("incorrect body granted B access: %d", got)
	}
	if got := uploadSourceAs(t, f, digest, data, "other@example.com"); got != 200 {
		t.Fatalf("verified same bytes %d", got)
	}
	if got := create(); got != 201 {
		t.Fatalf("verified upload refused B: %d", got)
	}
	reopened, err := New(f.cfg, Options{Source: testSource{exists: false}, Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.state.Meta.SourceOwners[digest][f.cfg.Account+"\x00tailnet:other@example.com"] {
		t.Fatal("source ownership not persisted")
	}
}

func TestSnapshotUploadRefusals(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, media, login string
		length             int64
		status             int
	}{
		{"unauthenticated", sourceMediaType, "", 0, 401},
		{"unsupported", "application/zip", "micah@example.com", 0, 422},
		{"too-large", sourceMediaType, "micah@example.com", sourceLimit + 1, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/api/v1alpha1/accounts/oyzu/sources/sha256:"+strings.Repeat("a", 64), nil)
			r.RemoteAddr = "127.0.0.1:1234"
			r.ContentLength = tc.length
			r.Header.Set("Content-Type", tc.media)
			r.Header.Set("Tailscale-User-Login", tc.login)
			w := httptest.NewRecorder()
			f.s.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRunCreateRequiresExactlyOneSource(t *testing.T) {
	base := `{"repository":{"provider":"github","name":"oyzuai/fleet"},"operation":{"kind":"build"}`
	for _, suffix := range []string{
		`}`, `,"commit":"` + testSHA + `","source":{"kind":"snapshot","digest":"sha256:` + strings.Repeat("a", 64) + `"}}`,
		`,"source":{"kind":"snapshot","digest":"bad"}}`,
		`,"source":{"kind":"snapshot","digest":"sha256:` + strings.Repeat("a", 64) + `","base_commit":""}}`,
	} {
		raw := []byte(base + suffix)
		var in RunCreate
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		if len(validateCreate(in, raw)) == 0 {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func putBlob(t *testing.T, f *fixture, digest string, data []byte, encoding string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest("PUT", "/api/v1alpha1/accounts/oyzu/blobs/"+digest, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Tailscale-User-Login", "micah@example.com")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Content-Encoding", encoding)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func sourceTestManifest(t *testing.T, f *fixture, content string) ([]byte, string) {
	t.Helper()
	blob := "sha256:" + hash([]byte(content))
	if status, raw := putBlob(t, f, blob, []byte(content), ""); status != 201 && status != 200 {
		t.Fatalf("blob upload %d %s", status, raw)
	}
	data, err := json.Marshal(runnerclient.SourceManifest{Entries: []runnerclient.SourceEntry{{Path: "file", Kind: "file", Mode: 0644, Mtime: f.s.now().UnixNano(), Size: int64(len(content)), Digest: blob}}})
	if err != nil {
		t.Fatal(err)
	}
	return data, blob
}

func TestManifestRefusesMissingBlobAndMissingLookup(t *testing.T) {
	f := newFixture(t)
	blob := "sha256:" + hash([]byte("not uploaded"))
	data, err := json.Marshal(runnerclient.SourceManifest{Entries: []runnerclient.SourceEntry{{Path: "file", Kind: "file", Size: 12, Digest: blob}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + hash(data)
	r := httptest.NewRequest("PUT", "/api/v1alpha1/accounts/oyzu/sources/"+digest, bytes.NewReader(data))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Tailscale-User-Login", "micah@example.com")
	r.Header.Set("Content-Type", sourceMediaType)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	var body struct {
		Code    string   `json:"code"`
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 422 || body.Code != "SOURCE_BLOBS_MISSING" || len(body.Missing) != 1 || body.Missing[0] != blob {
		t.Fatalf("missing response %d %s", w.Code, w.Body.String())
	}
	if len(f.s.state.Meta.SourceOwners[digest]) != 0 {
		t.Fatal("incomplete manifest granted ownership")
	}
	status, raw, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/sources/missing", "micah@example.com", map[string]any{"blobs": []string{blob}}, nil)
	if status != 200 || !strings.Contains(string(raw), blob) {
		t.Fatalf("missing lookup %d %s", status, raw)
	}
	if status, _ := putBlob(t, f, blob, []byte("not uploaded"), ""); status != 201 {
		t.Fatalf("blob upload %d", status)
	}
	status, raw, _ = f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/sources/missing", "other@example.com", map[string]any{"blobs": []string{blob}}, nil)
	if status != 200 || strings.Contains(string(raw), blob) {
		t.Fatalf("account shared lookup %d %s", status, raw)
	}
	if got := uploadSource(t, f, digest, data); got != 201 {
		t.Fatalf("complete manifest %d", got)
	}
	tooMany := make([]string, 10001)
	for i := range tooMany {
		tooMany[i] = blob
	}
	status, _, _ = f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/sources/missing", "micah@example.com", map[string]any{"blobs": tooMany}, nil)
	if status != 422 {
		t.Fatalf("oversized missing batch %d", status)
	}
	status, _, _ = f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/sources/missing", "", map[string]any{"blobs": []string{blob}}, nil)
	if status != 401 {
		t.Fatalf("anonymous lookup %d", status)
	}
}

func TestBlobUploadDecodedDigestAndImmutableDeduplication(t *testing.T) {
	f := newFixture(t)
	data := bytes.Repeat([]byte("compressible source\n"), 1000)
	digest := "sha256:" + hash(data)
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	compressed := encoder.EncodeAll(data, nil)
	if status, raw := putBlob(t, f, digest, compressed, "zstd"); status != 201 {
		t.Fatalf("compressed upload %d %s", status, raw)
	}
	if status, _ := putBlob(t, f, digest, data, ""); status != 200 {
		t.Fatalf("raw duplicate %d", status)
	}
	if status, _ := putBlob(t, f, digest, []byte("wrong"), ""); status != 422 {
		t.Fatalf("existing digest accepted wrong bytes %d", status)
	}
	if status, _ := putBlob(t, f, digest, compressed[:len(compressed)-1], "zstd"); status != 400 {
		t.Fatalf("truncated frame %d", status)
	}
	if status, _ := putBlob(t, f, digest, data, "gzip"); status != 422 {
		t.Fatalf("unsupported encoding %d", status)
	}
}
