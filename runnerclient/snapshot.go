package runnerclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const SourceMediaType = "application/vnd.oyzu.source.v1alpha1+json"
const SourceLimit int64 = 512 << 20
const SourceEntryLimit = 200000

// SourceManifest describes an immutable tree. Digests cover the original JSON
// bytes, not a reserialization of these DTOs. Modes are Unix permission bits;
// mtimes are integer Unix nanoseconds. Symlinks carry no file metadata.
type SourceManifest struct {
	Entries []SourceEntry `json:"entries"`
}

type SourceEntry struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode,omitempty"`
	Mtime  int64  `json:"mtime,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Digest string `json:"digest,omitempty"`
	Target string `json:"target,omitempty"`
}

func (e SourceEntry) MarshalJSON() ([]byte, error) {
	fields := map[string]any{"path": e.Path, "kind": e.Kind}
	switch e.Kind {
	case "file":
		fields["size"], fields["digest"] = e.Size, e.Digest
		fallthrough
	case "directory":
		fields["mode"], fields["mtime"] = e.Mode, e.Mtime
	case "symlink":
		fields["target"] = e.Target
	}
	return json.Marshal(fields)
}

func ValidSourceDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest[7:])
	return err == nil
}

func sourceRelative(name string) bool {
	if name == "" || !utf8.ValidString(name) || path.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".git" || part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

// sourceObject rejects duplicate keys, unknown/missing fields, nulls and trailing
// JSON. Typed decoding alone accepts duplicate keys and null scalar values.
func sourceObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("source JSON must be UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("expected source object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok || out[key] != nil {
			return nil, errors.New("duplicate source field")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("null source field")
		}
		out[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing source JSON")
	}
	return out, nil
}

// ParseSourceManifest validates the shared wire contract. Entries must be
// sorted, unique, bounded, and unable to write through another entry's link.
// Link resolution against the actual restored tree is the executor's duty.
func ParseSourceManifest(data []byte) (SourceManifest, error) {
	var out SourceManifest
	root, err := sourceObject(data)
	if err != nil || len(root) != 1 || root["entries"] == nil {
		return out, errors.New("expected entries-only source manifest")
	}
	var entries []json.RawMessage
	if err = json.Unmarshal(root["entries"], &entries); err != nil || len(entries) > SourceEntryLimit {
		return out, errors.New("invalid or oversized source entry list")
	}
	out.Entries = make([]SourceEntry, 0, len(entries))
	kinds := map[string]string{}
	links := map[string]string{}
	sizes := map[string]int64{}
	var total int64
	previous := ""
	for _, raw := range entries {
		fields, err := sourceObject(raw)
		if err != nil {
			return out, err
		}
		var e SourceEntry
		if err = json.Unmarshal(raw, &e); err != nil || !sourceRelative(e.Path) || e.Path <= previous {
			return out, errors.New("unsafe, duplicate or unsorted source entry")
		}
		allowed := []string{"path", "kind"}
		switch e.Kind {
		case "file":
			allowed = append(allowed, "mode", "mtime", "size", "digest")
			if !ValidSourceDigest(e.Digest) || e.Size < 0 || e.Size > SourceLimit-total {
				return out, errors.New("invalid file digest or source size exceeds 512 MiB")
			}
			if size, ok := sizes[e.Digest]; ok && size != e.Size {
				return out, errors.New("inconsistent blob size")
			}
			sizes[e.Digest] = e.Size
			total += e.Size
		case "directory":
			allowed = append(allowed, "mode", "mtime")
		case "symlink":
			allowed = append(allowed, "target")
			resolved := path.Clean(path.Join(path.Dir(e.Path), e.Target))
			if e.Target == "" || path.IsAbs(e.Target) || strings.ContainsAny(e.Target, "\\:\x00") || (resolved != "." && !sourceRelative(resolved)) {
				return out, errors.New("source link escapes tree")
			}
			links[e.Path] = e.Target
		default:
			return out, errors.New("unsupported source entry kind")
		}
		if len(fields) != len(allowed) || e.Mode > 0777 {
			return out, errors.New("unexpected source fields or mode")
		}
		for _, key := range allowed {
			if fields[key] == nil {
				return out, errors.New("missing source field")
			}
		}
		for parent := path.Dir(e.Path); parent != "."; parent = path.Dir(parent) {
			if kind, ok := kinds[parent]; ok && kind != "directory" {
				return out, errors.New("source entry has non-directory ancestor")
			}
		}
		kinds[e.Path] = e.Kind
		previous = e.Path
		out.Entries = append(out.Entries, e)
	}
	for name, target := range links {
		if err := sourceLinkInside(name, target, links); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Resolve symlinks before interpreting subsequent '..' components, just as
// the filesystem does. Cleaning first could conceal a traversal through a link
// to an ancestor. The executor still checks actual resolution after creation.
func sourceLinkInside(name, target string, links map[string]string) error {
	var resolved []string
	if parent := path.Dir(name); parent != "." {
		resolved = strings.Split(parent, "/")
	}
	pending := strings.Split(target, "/")
	followed := 0
	for len(pending) != 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return errors.New("source link escapes tree")
			}
			resolved = resolved[:len(resolved)-1]
			continue
		case ".git":
			return errors.New("source link references .git")
		}
		candidate := strings.Join(append(resolved, part), "/")
		if next, ok := links[candidate]; ok {
			followed++
			if followed > 40 {
				return errors.New("source link cannot be resolved")
			}
			pending = append(strings.Split(next, "/"), pending...)
		} else {
			resolved = append(resolved, part)
		}
	}
	return nil
}
