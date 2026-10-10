// Package manager is the pool manager: it holds a manager identity whose
// Ed25519 private key never leaves this machine, logs in to runs with it,
// rotates it, claims jobs for its pool and starts a fresh runner for each one.
package manager

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is what a manager keeps between runs, in its state directory. The
// private keys are separate PEM files beside it, readable only by the owner
// where the OS supports that.
type State struct {
	Server string `json:"server"`
	// Audience is the aud runs expects on this manager's assertions.
	Audience  string `json:"audience"`
	ManagerID int64  `json:"manager_id"`
	Pool      string `json:"pool"`
	Name      string `json:"name"`
	// Current is the key the manager logs in with.
	Current Key `json:"current"`
	// Next is a key being rotated in: generated, maybe registered, not yet
	// used to log in. Empty when no rotation is under way.
	Next *Key `json:"next,omitempty"`
}

// Key names a key file and, once registered, its id at runs.
type Key struct {
	ID      int64     `json:"id"`
	File    string    `json:"file"`
	Created time.Time `json:"created"`
}

const stateFile = "manager.json"

// Store reads and writes a state directory.
type Store struct {
	Dir string
}

// Load reads the state. It returns os.ErrNotExist before enrollment.
func (s Store) Load() (*State, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, stateFile))
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", stateFile, err)
	}
	return &st, nil
}

// Save writes the state atomically.
func (s Store) Save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.Dir, stateFile), append(b, '\n'))
}

// NewKey generates a key and writes its private half to a new file.
func (s Store) NewKey(now time.Time) (Key, ed25519.PrivateKey, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Key{}, nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Key{}, nil, err
	}
	name := fmt.Sprintf("key-%d.pem", now.UnixNano())
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeAtomic(filepath.Join(s.Dir, name), pemBytes); err != nil {
		return Key{}, nil, err
	}
	return Key{File: name, Created: now.UTC()}, priv, nil
}

// PrivateKey reads a key file.
func (s Store) PrivateKey(k Key) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, k.File))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", k.File)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", k.File, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", k.File)
	}
	return priv, nil
}

// Remove deletes a key file that is no longer used.
func (s Store) Remove(k Key) error {
	err := os.Remove(filepath.Join(s.Dir, k.File))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// writeAtomic writes b to path through a temporary file, owner-only.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// CreateTemp already makes the file 0600 on Unix. Windows has no mode bits
	// beyond read-only; there the state directory's ACL protects the keys.
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
