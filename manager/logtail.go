package manager

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"
)

// LogTailBytes is how much of a failed executor's output the manager keeps
// in its failure detail: enough for a startup, TLS or reporting error,
// small enough for the release reason runs records.
const LogTailBytes = 2 << 10

// LogTailLines is how many lines a driver asks its engine for before the
// tail is cut to LogTailBytes.
const LogTailLines = 40

// credentialish matches what looks like a bearer credential: JWTs, which
// startup, job and ID tokens are, and the value after "Bearer".
var credentialish = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{8,}`)

// LogTail is the masked end of an executor's output, for an Exit's Detail:
// the last LogTailBytes, starting on a line, with every secret in secrets
// and anything shaped like a bearer credential replaced by ***. The
// executor masks the job's own secrets before it prints anything; this
// covers what only the manager knows, such as the startup token.
func LogTail(out []byte, secrets ...string) string {
	s := string(bytes.ToValidUTF8(out, []byte("\uFFFD")))
	for _, v := range secrets {
		if len(v) >= 6 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	s = credentialish.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) > 6 && strings.EqualFold(m[:6], "bearer") {
			return m[:6] + " ***"
		}
		return "***"
	})
	s = strings.TrimRight(s, "\r\n\t ")
	if len(s) > LogTailBytes {
		s = s[len(s)-LogTailBytes:]
		for len(s) > 0 && !utf8.RuneStart(s[0]) {
			s = s[1:]
		}
		if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
			s = s[i+1:]
		}
		s = "…\n" + s
	}
	return s
}

// WithLogTail adds a log tail to an exit's detail, when there is one.
func (e Exit) WithLogTail(tail string) Exit {
	if tail == "" {
		return e
	}
	if e.Detail != "" {
		e.Detail += "; "
	}
	e.Detail += "last output:\n" + tail
	return e
}
