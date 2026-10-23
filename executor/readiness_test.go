package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessBootstrapWaitsForCompleteManagerHandoff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup")
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type reply struct {
		token string
		err   error
	}
	got := make(chan reply, 1)
	go func() { token, err := readReadinessStartupToken(ctx, path); got <- reply{token, err} }()
	select {
	case <-got:
		t.Fatal("bootstrap read a token before its completed handoff marker")
	case <-time.After(30 * time.Millisecond):
	}
	if err := os.WriteFile(path, []byte("complete-one-use-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".ready", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	result := <-got
	if result.err != nil || result.token != "complete-one-use-token" {
		t.Fatal("complete handoff was not read", result.err)
	}
	for _, file := range []string{path, path + ".ready"} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatal("handoff material remained for job code")
		}
	}
}
