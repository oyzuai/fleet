package poolserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// TokenCommand manages caller credentials without requiring a bootable config.
// The caller must serialize administrative edits and restart the server afterward.
func TokenCommand(action, path, name string, out io.Writer) error {
	f, err := openPrivateFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err = decodeJSON(io.LimitReader(f, 1<<20), &raw); err != nil {
		return err
	}
	var callers map[string]json.RawMessage
	if b := raw["callers"]; len(b) > 0 {
		if err = json.Unmarshal(b, &callers); err != nil {
			return err
		}
	}
	if callers == nil {
		callers = map[string]json.RawMessage{}
	}
	var tokens []TokenCaller
	if b := callers["tokens"]; len(b) > 0 {
		if err = json.Unmarshal(b, &tokens); err != nil {
			return err
		}
	}
	if action == "list" {
		for _, t := range tokens {
			if _, err = fmt.Fprintln(out, t.Name); err != nil {
				return err
			}
		}
		return nil
	}
	if !tokenNameRE.MatchString(name) {
		return errors.New("name must match [a-z0-9-]{1,64}")
	}
	index := -1
	for i, t := range tokens {
		if t.Name == name {
			index = i
		}
	}
	var token string
	switch action {
	case "create":
		if index >= 0 {
			return errors.New("token name already exists")
		}
		b := make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		token = "oyzp_" + base64.RawURLEncoding.EncodeToString(b)
		tokens = append(tokens, TokenCaller{Name: name, SHA256: hash([]byte(token))})
	case "revoke":
		if index < 0 {
			return errors.New("token name not found")
		}
		tokens = append(tokens[:index], tokens[index+1:]...)
	default:
		return errors.New("expected token create, revoke or list")
	}
	callers["tokens"], err = json.Marshal(tokens)
	if err != nil {
		return err
	}
	raw["callers"], err = json.Marshal(callers)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pool-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("config ownership unavailable")
	}
	current, err := tmp.Stat()
	if err != nil {
		return err
	}
	owner := current.Sys().(*syscall.Stat_t)
	if owner.Uid != stat.Uid || owner.Gid != stat.Gid {
		if err = tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err = tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	if token != "" {
		_, err = fmt.Fprintln(out, token)
	}
	return err
}
