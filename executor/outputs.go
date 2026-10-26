package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"github.com/oyzuai/fleet/runnerclient"
)

const (
	// ManifestPath is where oyzu build writes its build manifest, relative
	// to the checkout.
	ManifestPath = "dist/manifest.json"
	// ManifestMediaType is the v1alpha1 build manifest's media type.
	ManifestMediaType = "application/vnd.oyzu.build-manifest.v1alpha1+json"
	// MaxOutputs bounds the outputs one finish reports; runs refuses more.
	MaxOutputs = 1000
	// maxManifest bounds the manifest the runner reads. Directory artifacts
	// list their entries, so a manifest can be large; only artifacts are sent.
	maxManifest = 64 << 20
)

var outputDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// buildManifest is the part of the v1alpha1 build manifest runs reads.
type buildManifest struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	RunID         string `json:"runId"`
	Status        string `json:"status"`
	Reports       []struct {
		Target string `json:"target"`
		Kind   string `json:"kind"`
		Format string `json:"format"`
		Status string `json:"status"`
		Path   string `json:"path"`
		Digest string `json:"digest"`
	} `json:"reports"`
	Artifacts     []struct {
		Target    string `json:"target"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		MediaType string `json:"mediaType"`
		Path      string `json:"path"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		OCIDigest string `json:"ociDigest"`
	} `json:"artifacts"`
}

// readOutputs lists what the build in dir wrote by its build manifest: the
// manifest, then each artifact at its path under dist. A build that wrote
// no manifest has no outputs and is not an error.
func readOutputs(dir string) ([]runnerclient.Output, error) {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(ManifestPath)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxManifest {
		return nil, fmt.Errorf("%s is larger than %d MiB", ManifestPath, maxManifest>>20)
	}
	return manifestOutputs(raw)
}

// manifestOutputs indexes the exact producer record. A retained handoff retry
// returns that sealed record instead of rewriting the failed invocation on disk.
func manifestOutputs(raw []byte) ([]runnerclient.Output, error) {
	m, err := parseBuildManifest(raw)
	if err != nil {
		return nil, err
	}
	if len(m.Artifacts)+1 > MaxOutputs {
		return nil, fmt.Errorf("%s lists %d artifacts; runs takes at most %d", ManifestPath, len(m.Artifacts), MaxOutputs-1)
	}
	sum := sha256.Sum256(raw)
	out := []runnerclient.Output{{Path: ManifestPath, Kind: "manifest", MediaType: ManifestMediaType,
		Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(raw))}}
	for _, a := range m.Artifacts {
		if !fs.ValidPath(a.Path) || a.Path == "." {
			return nil, fmt.Errorf("artifact %s/%s has an invalid path", a.Target, a.Name)
		}
		if a.Target == "" || a.Name == "" || a.Version == "" || a.MediaType == "" || !outputDigest.MatchString(a.Digest) ||
			(a.OCIDigest != "" && !outputDigest.MatchString(a.OCIDigest)) || a.Size < 0 {
			return nil, fmt.Errorf("artifact %s/%s lacks a target, name, version, media type or sha256 digest", a.Target, a.Name)
		}
		out = append(out, runnerclient.Output{Path: path.Join(path.Dir(ManifestPath), a.Path), Kind: "artifact", MediaType: a.MediaType, Digest: a.Digest, Size: a.Size,
			Target: a.Target, Name: a.Name, Version: a.Version, OCIDigest: a.OCIDigest})
	}
	return out, nil
}

func parseBuildManifest(raw []byte) (buildManifest, error) {
	var m buildManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("%s is not JSON: %w", ManifestPath, err)
	}
	if m.SchemaVersion != "v1alpha1" || m.Kind != "build-manifest" {
		return m, fmt.Errorf("%s is not a v1alpha1 build manifest", ManifestPath)
	}
	return m, nil
}
