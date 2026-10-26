package poolserver

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func storedTestSource(t *testing.T, f *fixture, content string) (string, string) {
	t.Helper()
	data, blob := sourceTestManifest(t, f, content)
	digest := "sha256:" + hash(data)
	if status := uploadSource(t, f, digest, data); status != 201 {
		t.Fatalf("manifest upload %d", status)
	}
	return digest, blob
}

func assertSourceFile(t *testing.T, name string, exists bool) {
	t.Helper()
	_, err := os.Stat(name)
	if exists && err != nil {
		t.Fatalf("expected %s: %v", name, err)
	}
	if !exists && !os.IsNotExist(err) {
		t.Fatalf("expected absent %s: %v", name, err)
	}
}

func TestSourceSweepRetentionProtectsQueuedAndRunning(t *testing.T) {
	for _, state := range []string{"queued", "running"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			old, oldBlob := storedTestSource(t, f, "unreferenced")
			keep, keepBlob := storedTestSource(t, f, "active")
			body := RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Source: &SnapshotSource{Kind: "snapshot", Digest: keep}, Operation: Operation{Kind: "build"}}
			status, raw, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/runs", "micah@example.com", body, nil)
			if status != 201 {
				t.Fatalf("run %d %s", status, raw)
			}
			var run Run
			if err := json.Unmarshal(raw, &run); err != nil {
				t.Fatal(err)
			}
			f.s.state.Runs[run.ID].Run.State = state
			f.s.state.Jobs[f.s.state.Runs[run.ID].JobID].State = state
			f.now.Add(int64((8 * 24 * time.Hour) / time.Second))
			if err := f.s.sweepSources(); err != nil {
				t.Fatal(err)
			}
			assertSourceFile(t, f.s.sourcePath(old), false)
			assertSourceFile(t, f.s.blobPath(oldBlob), false)
			assertSourceFile(t, f.s.sourcePath(keep), true)
			assertSourceFile(t, f.s.blobPath(keepBlob), true)
			if len(f.s.state.Meta.SourceOwners[old]) != 0 {
				t.Fatal("evicted source retained owners")
			}
		})
	}
}

func TestSourceSweepQuotaEvictsLeastRecentlyUsed(t *testing.T) {
	f := newFixture(t)
	old, oldBlob := storedTestSource(t, f, "old")
	f.now.Add(1)
	newer, newerBlob := storedTestSource(t, f, "new")
	f.now.Add(int64((2 * time.Hour) / time.Second))
	newRecord := f.s.state.Meta.Sources[newer]
	f.s.cfg.SourceQuota = newRecord.Size + newRecord.Blobs[newerBlob]
	if err := f.s.sweepSources(); err != nil {
		t.Fatal(err)
	}
	assertSourceFile(t, f.s.sourcePath(old), false)
	assertSourceFile(t, f.s.blobPath(oldBlob), false)
	assertSourceFile(t, f.s.sourcePath(newer), true)
	assertSourceFile(t, f.s.blobPath(newerBlob), true)
}

func TestSourceSweepNewBlobGraceAndRerunUpload(t *testing.T) {
	f := newFixture(t)
	data := []byte("in-progress upload")
	digest := "sha256:" + hash(data)
	if status, _ := putBlob(t, f, digest, data, ""); status != 201 {
		t.Fatalf("upload %d", status)
	}
	f.now.Add(3599)
	if err := f.s.sweepSources(); err != nil {
		t.Fatal(err)
	}
	assertSourceFile(t, f.s.blobPath(digest), true)
	f.now.Add(1)
	if err := f.s.sweepSources(); err != nil {
		t.Fatal(err)
	}
	assertSourceFile(t, f.s.blobPath(digest), false)
	status, raw, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/sources/missing", "micah@example.com", map[string]any{"blobs": []string{digest}}, nil)
	var response struct {
		Missing []string `json:"missing"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if status != 200 || len(response.Missing) != 1 || response.Missing[0] != digest {
		t.Fatalf("cleaned blob missing lookup %d %s", status, raw)
	}
	if status, _ := putBlob(t, f, digest, data, ""); status != 201 {
		t.Fatalf("reupload %d", status)
	}
}

func TestSourceLastUsedRefreshesOnUploadAndRunCreate(t *testing.T) {
	f := newFixture(t)
	data, _ := sourceTestManifest(t, f, "refresh")
	digest := "sha256:" + hash(data)
	if status := uploadSource(t, f, digest, data); status != 201 {
		t.Fatalf("upload %d", status)
	}
	f.now.Add(3600)
	if status := uploadSource(t, f, digest, data); status != 200 {
		t.Fatalf("refresh upload %d", status)
	}
	if !f.s.state.Meta.Sources[digest].LastUsed.Equal(f.s.now()) {
		t.Fatal("upload did not refresh last_used")
	}
	f.now.Add(3600)
	body := RunCreate{Repository: Repository{Provider: "github", Name: "oyzuai/fleet"}, Source: &SnapshotSource{Kind: "snapshot", Digest: digest}, Operation: Operation{Kind: "build"}}
	status, raw, _ := f.request(t, "POST", "/api/v1alpha1/accounts/oyzu/runs", "micah@example.com", body, nil)
	if status != 201 || !f.s.state.Meta.Sources[digest].LastUsed.Equal(f.s.now()) {
		t.Fatalf("run did not refresh last_used %d %s", status, raw)
	}
}

func TestSourceStartupSweepUsesPersistedLastUsed(t *testing.T) {
	f := newFixture(t)
	digest, blob := storedTestSource(t, f, "expired on restart")
	f.now.Add(int64((8 * 24 * time.Hour) / time.Second))
	reopened, err := New(f.cfg, Options{Source: testSource{}, Now: f.s.now})
	if err != nil {
		t.Fatal(err)
	}
	assertSourceFile(t, reopened.sourcePath(digest), false)
	assertSourceFile(t, reopened.blobPath(blob), false)
	if len(reopened.state.Meta.SourceOwners[digest]) != 0 {
		t.Fatal("startup sweep retained ownership")
	}
}
