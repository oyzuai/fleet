package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// pullSecrets fetches the job's build secrets after startup authorization,
// with the job token, and returns them as environment entries: a variable's
// value, or for a file secret the path of a 0400 file in a private directory
// that cleanup removes. Every value is handed to mask before it is used, so
// the log never shows it. Only the variables the job spec named are
// accepted.
func pullSecrets(ctx context.Context, cfg Config, token string, want []string, mask func(string)) ([]string, func(), error) {
	cleanup := func() {}
	secrets, err := cfg.Client.Secrets(ctx, token)
	if err != nil {
		return nil, cleanup, err
	}
	defer func() {
		for _, s := range secrets {
			clear(s.Value)
		}
	}()
	got := make([]string, 0, len(secrets))
	for _, s := range secrets {
		mask(string(s.Value))
		got = append(got, s.Variable)
	}
	slices.Sort(got)
	expected := slices.Clone(want)
	slices.Sort(expected)
	if !slices.Equal(got, expected) {
		return nil, cleanup, fmt.Errorf("runs released %v, but the job names %v", got, expected)
	}

	var dir string
	var env []string
	for _, s := range secrets {
		if !s.File {
			if !utf8.Valid(s.Value) || strings.ContainsRune(string(s.Value), 0) {
				return nil, cleanup, fmt.Errorf("%s is not text; map it as a file", s.Variable)
			}
			env = append(env, s.Variable+"="+string(s.Value))
			continue
		}
		if dir == "" {
			if dir, err = os.MkdirTemp(cfg.SecretsDir, "oyzu-secrets-"); err != nil {
				return nil, cleanup, fmt.Errorf("create the secrets directory: %w", err)
			}
			cleanup = func() { _ = os.RemoveAll(dir) }
		}
		path := filepath.Join(dir, s.Variable)
		if err := writeSecretFile(path, s.Value); err != nil {
			return nil, cleanup, fmt.Errorf("write %s: %w", s.Variable, err)
		}
		env = append(env, s.Variable+"="+path)
	}
	return env, cleanup, nil
}

// writeSecretFile creates path, readable only by the runner's user.
func writeSecretFile(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	_, werr := f.Write(value)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

// withEnv sets entries in env, replacing any inherited value of the same
// variable.
func withEnv(env, entries []string) []string {
	set := map[string]bool{}
	for _, e := range entries {
		name, _, _ := strings.Cut(e, "=")
		set[name] = true
	}
	out := make([]string, 0, len(env)+len(entries))
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		if !set[name] {
			out = append(out, e)
		}
	}
	return append(out, entries...)
}
