package runnerclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
)

const (
	ActionJob        = "action"
	ActionRuntime    = "linux-container"
	MaxActionBytes   = 16 << 20
	MaxActionLogs    = 1 << 20
	MaxActionWire    = 32 << 20
	MaxActionEntries = 10000
)

// ActionAssignment is server-admitted command data, never a native source job.
// InstanceID and OperationID are binding metadata, not caller authority.
type ActionAssignment struct {
	InstanceID       string            `json:"instance_id"`
	OperationID      string            `json:"operation_id"`
	Image            string            `json:"image"`
	Arguments        []string          `json:"arguments"`
	Environment      map[string]string `json:"environment,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
	OutputPaths      []string          `json:"output_paths,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds"`
	NanoCPUs         int64             `json:"nano_cpus"`
	MemoryBytes      int64             `json:"memory_bytes"`
	PidsLimit        int64             `json:"pids_limit"`
}

type ActionFile struct {
	Path       string `json:"path"`
	Data       []byte `json:"data"`
	Executable bool   `json:"executable,omitempty"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

type ActionInputs struct {
	Files       []ActionFile `json:"files,omitempty"`
	Directories []string     `json:"directories,omitempty"`
}

// ExitCode describes a process result; ErrorCode describes a service failure.
// A nonzero process exit alone is not a service failure.
type ActionCompletion struct {
	ExitCode             *int         `json:"exit_code,omitempty"`
	Stdout               []byte       `json:"stdout,omitempty"`
	Stderr               []byte       `json:"stderr,omitempty"`
	Files                []ActionFile `json:"files,omitempty"`
	Directories          []string     `json:"directories,omitempty"`
	ErrorCode            string       `json:"error_code,omitempty"`
	Message              string       `json:"message,omitempty"`
	TerminationConfirmed bool         `json:"termination_confirmed"`
}

var actionImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)
var actionEnv = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ActionPath permits only portable, canonical paths below the private root.
func ActionPath(p string) bool {
	return p != "" && len(p) <= 4096 && p != "." && p != ".." && !strings.HasPrefix(p, "../") &&
		!strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\\:\x00\r\n")
}

func (a ActionAssignment) Validate() error {
	if a.InstanceID == "" || a.OperationID == "" || !actionImage.MatchString(a.Image) || len(a.Arguments) == 0 || a.Arguments[0] == "" ||
		a.TimeoutSeconds <= 0 || a.TimeoutSeconds > 3600 || a.NanoCPUs <= 0 || a.MemoryBytes <= 0 || a.PidsLimit <= 0 ||
		(a.WorkingDirectory != "" && !ActionPath(a.WorkingDirectory)) || len(a.OutputPaths) > MaxActionEntries {
		return errors.New("invalid admitted action assignment")
	}
	for _, arg := range a.Arguments {
		if strings.ContainsRune(arg, 0) {
			return errors.New("invalid action argument")
		}
	}
	for name, value := range a.Environment {
		if !actionEnv.MatchString(name) || strings.ContainsRune(value, 0) {
			return errors.New("invalid action environment")
		}
	}
	seen := map[string]bool{}
	for _, p := range a.OutputPaths {
		if !ActionPath(p) || seen[p] {
			return errors.New("invalid action output path")
		}
		seen[p] = true
	}
	b, err := json.Marshal(a)
	if err != nil || len(b) > 1<<20 {
		return errors.New("oversized action assignment")
	}
	return nil
}

func (in ActionInputs) Validate() error {
	if len(in.Files)+len(in.Directories) > MaxActionEntries {
		return errors.New("too many action files")
	}
	entries := map[string]bool{}
	total := int64(0)
	for _, f := range in.Files {
		sum := sha256.Sum256(f.Data)
		if !ActionPath(f.Path) || entries[f.Path] || f.Size != int64(len(f.Data)) || f.SHA256 != hex.EncodeToString(sum[:]) {
			return errors.New("invalid action file identity or path")
		}
		entries[f.Path] = true
		total += f.Size
		if total > MaxActionBytes {
			return errors.New("action files exceed byte limit")
		}
	}
	for _, d := range in.Directories {
		if !ActionPath(d) || entries[d] {
			return errors.New("invalid action directory")
		}
		entries[d] = true
	}
	files := map[string]bool{}
	for _, f := range in.Files {
		files[f.Path] = true
	}
	for p := range entries {
		for parent := path.Dir(p); parent != "."; parent = path.Dir(parent) {
			if files[parent] {
				return errors.New("action file is an ancestor of another entry")
			}
		}
	}
	return nil
}

func (c *Client) ActionInputs(ctx context.Context, token string) (ActionInputs, error) {
	var out ActionInputs
	err := c.do(ctx, "job/action/inputs", token, nil, &out)
	if err == nil {
		err = out.Validate()
	}
	return out, err
}

func (c *Client) ActionFinish(ctx context.Context, token string, completion ActionCompletion) error {
	if err := (ActionInputs{Files: completion.Files, Directories: completion.Directories}).Validate(); err != nil {
		return err
	}
	if len(completion.Stdout)+len(completion.Stderr) > MaxActionLogs {
		return errors.New("action logs exceed byte limit")
	}
	b, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	if len(b) > MaxActionWire {
		return errors.New("action completion exceeds wire limit")
	}
	return c.do(ctx, "job/action/finish", token, completion, nil)
}
