package runnerclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceManifestStrictContract(t *testing.T) {
	file := `{"digest":"sha256:` + strings.Repeat("a", 64) + `","kind":"file","mode":420,"mtime":123456789,"path":"file","size":1}`
	valid := `{"entries":[` + file + `]}`
	if _, err := ParseSourceManifest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"entries":null}`, `{"entries":[],"entries":[]}`, `{"entries":[],"unknown":1}`,
		valid + `{}`, `{"entries":[` + file + `,` + file + `]}`,
		strings.Replace(valid, `"size":1`, `"size":-1`, 1),
		strings.Replace(valid, `"size":1`, `"size":536870913`, 1),
		strings.Replace(valid, `"mode":420`, `"mode":null`, 1),
		strings.Replace(valid, `"mode":420`, `"mode":512`, 1),
		strings.Replace(valid, `"mtime":123456789`, `"mtime":1.5`, 1),
		strings.Replace(valid, `"mode":420,`, ``, 1),
		strings.Replace(valid, `"size":1`, `"size":1,"extra":0`, 1),
		strings.Replace(valid, `"path":"file"`, `"path":"../file"`, 1),
		strings.Replace(valid, `"path":"file"`, `"path":"/file"`, 1),
		strings.Replace(valid, `"path":"file"`, `"path":".git/config"`, 1),
		strings.Replace(valid, `"path":"file"`, `"path":"C:file"`, 1),
		`{"entries":[{"kind":"symlink","path":"link","target":"../outside"}]}`,
		`{"entries":[{"kind":"symlink","path":"link","target":"/etc/passwd"}]}`,
		`{"entries":[{"kind":"symlink","path":"a","target":"."},{"kind":"symlink","path":"b","target":"a/../outside"}]}`,
		`{"entries":[{"kind":"symlink","path":"a","target":"b"},{"kind":"symlink","path":"b","target":"a"}]}`,
		`{"entries":[{"kind":"symlink","path":"link","target":"file"},` + strings.Replace(file, `"path":"file"`, `"path":"link/file"`, 1) + `]}`,
		`{"entries":[{"kind":"device","path":"device"}]}`,
	} {
		if _, err := ParseSourceManifest([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestSourceManifestEntryAndLogicalSizeLimits(t *testing.T) {
	entries := make([]SourceEntry, SourceEntryLimit+1)
	data, err := json.Marshal(SourceManifest{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSourceManifest(data); err == nil {
		t.Fatal("oversized entry list accepted")
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	data, err = json.Marshal(SourceManifest{Entries: []SourceEntry{
		{Path: "a", Kind: "file", Digest: digest, Size: SourceLimit},
		{Path: "b", Kind: "file", Digest: digest, Size: SourceLimit},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSourceManifest(data); err == nil {
		t.Fatal("logical size of repeated blob was not counted")
	}
}
