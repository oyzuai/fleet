package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/poolserver"
	"github.com/oyzuai/fleet/runnerclient"
)

// Exercise the actual upload/run/grant/restore boundary, without an image,
// subprocess, live pool, or GitHub credential.
func TestSnapshotPoolManifestBlobRoundTrip(t *testing.T) {
	var cfg poolserver.Config
	cfg.Account = "test"
	cfg.PublicURL = "https://pool.test"
	cfg.StateDir = t.TempDir()
	cfg.Repositories = []string{"oyzuai/fleet"}
	cfg.Callers.TailnetUsers = []string{"test@example.com"}

	cfg.EnrollmentTokenSHA256 = snapshotDigest([]byte("enroll"))[7:]
	pool, err := poolserver.New(cfg, poolserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(pool)
	defer srv.Close()
	request := func(method, path, media string, data []byte, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Tailscale-User-Login", "test@example.com")
		req.Header.Set("Content-Type", media)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s %v", method, path, resp.StatusCode, body, err)
		}
		return body
	}
	content := []byte("real pool source file")
	blob := snapshotDigest(content)
	base := "/api/v1alpha1/accounts/test"
	request("POST", base+"/sources/missing", "application/json", []byte(`{"blobs":["`+blob+`"]}`), 200)
	request("PUT", base+"/blobs/"+blob, "application/octet-stream", content, 201)
	manifest := snapshotManifest(t, runnerclient.SourceEntry{Path: "input.txt", Kind: "file", Mode: 0644, Mtime: time.Now().UnixNano(), Size: int64(len(content)), Digest: blob})
	digest := snapshotDigest(manifest)
	request("PUT", base+"/sources/"+digest, runnerclient.SourceMediaType, manifest, 201)
	body, err := json.Marshal(poolserver.RunCreate{Repository: poolserver.Repository{Provider: "github", Name: "oyzuai/fleet"}, Source: &poolserver.SnapshotSource{Kind: "snapshot", Digest: digest}, Operation: poolserver.Operation{Kind: "build"}})
	if err != nil {
		t.Fatal(err)
	}
	request("POST", base+"/runs", "application/json", body, 201)
	client := runnerclient.New(srv.URL, srv.Client())
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := client.Enroll(ctx, "enroll", "test", pub)
	if err != nil {
		t.Fatal(err)
	}
	claims := assertion.New(enrolled.ManagerID, "oyzu-runs", "source-round-trip", time.Now(), time.Minute)
	signed, err := assertion.Sign(priv, enrolled.KeyID, assertion.TypeLogin, claims)
	if err != nil {
		t.Fatal(err)
	}
	access, err := client.Login(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Report(ctx, access.Token, runnerclient.Report{Facts: map[string]string{manager.FactIsolation: "container", manager.FactEgress: manager.EgressEnforced, manager.FactUntrusted: manager.UntrustedAccepted}}); err != nil {
		t.Fatal(err)
	}
	claim, err := client.Claim(ctx, access.Token)
	if err != nil || claim == nil {
		t.Fatalf("claim %v", err)
	}
	started, err := client.Start(ctx, claim.StartupToken, runnerclient.StartupAssignment{})
	if err != nil {
		t.Fatal(err)
	}
	source, err := client.Source(ctx, started.JobToken)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	source.URL = srv.URL + u.RequestURI()
	root := t.TempDir()
	if err := restoreSnapshot(ctx, Config{Client: client, WorkDir: root}, source); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "input.txt"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("round-trip %q %v", got, err)
	}
}
