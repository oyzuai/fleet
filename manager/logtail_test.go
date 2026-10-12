package manager

import (
	"strings"
	"testing"
)

func TestLogTailMasksAndBounds(t *testing.T) {
	jwt := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJqb2IifQ.c2lnbmF0dXJl"
	out := "starting\nstartup token st-0123456789 refused\nAuthorization: Bearer abcdefghijkl\ntoken " + jwt + "\n"
	got := LogTail([]byte(out), "st-0123456789")
	for _, leaked := range []string{"st-0123456789", "abcdefghijkl", jwt} {
		if strings.Contains(got, leaked) {
			t.Fatalf("tail leaks %q:\n%s", leaked, got)
		}
	}
	if !strings.Contains(got, "startup token *** refused") || !strings.Contains(got, "Bearer ***") {
		t.Fatalf("tail = %q", got)
	}

	long := strings.Repeat("line of output é\n", 1000) + "the real error"
	got = LogTail([]byte(long))
	if len(got) > LogTailBytes+8 || !strings.HasSuffix(got, "the real error") || !strings.HasPrefix(got, "…\nline of output") {
		t.Fatalf("long tail (%d bytes) = %q…", len(got), got[:40])
	}
	if LogTail(nil) != "" {
		t.Fatal("empty output has a tail")
	}
	e := Exit{Reason: ExitExited, Code: 1, Detail: "container c"}.WithLogTail("boom")
	if e.Detail != "container c; last output:\nboom" {
		t.Fatalf("detail = %q", e.Detail)
	}
}
