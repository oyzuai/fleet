package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// manifest is a v1alpha1 build manifest with an image and a chart, trimmed
// to the fields runs reads plus some it ignores.
var manifest = `{
  "schemaVersion": "v1alpha1", "kind": "build-manifest", "status": "succeeded",
  "targets": [{"id": "api"}],
  "artifacts": [
    {"id": "api/primary", "target": "api", "variant": {}, "name": "primary", "producer": "api:package", "kind": "oci-image",
     "version": "1.4.0", "mediaType": "application/vnd.oci.image.manifest.v1+json", "path": "api/image.oci.tar",
     "digest": "` + digestOf('4') + `", "ociDigest": "` + digestOf('1') + `", "size": 123},
    {"id": "api/chart", "target": "api", "variant": {}, "name": "chart", "producer": "api:chart", "kind": "chart",
     "version": "1.4.0", "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "path": "api/api-1.4.0.tgz",
     "digest": "` + digestOf('5') + `", "size": 45}
  ]
}`

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dist", "manifest.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadOutputs(t *testing.T) {
	outs, err := readOutputs(writeManifest(t, manifest))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(manifest))
	if len(outs) != 3 || outs[0].Kind != "manifest" || outs[0].Path != ManifestPath ||
		outs[0].Digest != "sha256:"+hex.EncodeToString(sum[:]) || outs[0].Size != int64(len(manifest)) {
		t.Fatalf("manifest output = %+v", outs)
	}
	if o := outs[1]; o.Path != "dist/api/image.oci.tar" || o.Kind != "artifact" || o.Target != "api" || o.Name != "primary" ||
		o.Version != "1.4.0" || o.Digest != digestOf('4') || o.OCIDigest != digestOf('1') || o.Size != 123 {
		t.Fatalf("image = %+v", o)
	}
	if o := outs[2]; o.Path != "dist/api/api-1.4.0.tgz" || o.Name != "chart" || o.OCIDigest != "" {
		t.Fatalf("chart = %+v", o)
	}
}

func TestReadOutputsWithoutAManifest(t *testing.T) {
	outs, err := readOutputs(t.TempDir())
	if err != nil || outs != nil {
		t.Fatalf("readOutputs = %+v, %v", outs, err)
	}
}

func TestReadOutputsRefusesBadManifests(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       `{`,
		"not a manifest": `{"schemaVersion":"v1","kind":"build-preview","artifacts":[]}`,
		"climbs out":     strings.Replace(manifest, `"api/image.oci.tar"`, `"../../etc/passwd"`, 1),
		"absolute":       strings.Replace(manifest, `"api/image.oci.tar"`, `"/etc/passwd"`, 1),
		"no version":     strings.Replace(manifest, `"version": "1.4.0", "mediaType": "application/vnd.oci`, `"mediaType": "application/vnd.oci`, 1),
		"bad digest":     strings.Replace(manifest, digestOf('5'), "md5:abc", 1),
	} {
		if _, err := readOutputs(writeManifest(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A succeeded build sends what its manifest lists; a manifest the runner
// cannot read publishes nothing and says so, without failing the build.
func TestRunSendsBuildOutputs(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_OYZU_MANIFEST", manifest)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "succeeded" || len(o.Outputs) != 3 || o.Outputs[1].Target != "api" {
		t.Fatalf("outcome = %+v", o)
	}

	runs, cfg, _ = setup(t, buildJob("build", "oyzu", "build"))
	t.Setenv("FAKE_OYZU_MANIFEST", `{`)
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if o := runs.finished; o == nil || o.State != "succeeded" || len(o.Outputs) != 0 ||
		!strings.Contains(o.Summary, "Nothing from this build is published") {
		t.Fatalf("outcome = %+v", o)
	}
}
